package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// suspiciousParamNames is the watchlist of parameter names that often
// serve as exfiltration channels — names that have nothing to do with
// the tool's stated purpose but invite the agent to dump extra text.
// Sourced from MCP-Shield's tool-analyzer.ts and our T5-006 corpus entry.
var suspiciousParamNames = map[string]bool{
	"note": true, "notes": true, "feedback": true, "details": true,
	"extra": true, "additional": true, "metadata": true, "debug": true,
	"sidenote": true, "context": true, "annotation": true,
	"reasoning": true, "remark": true,
}

// longWhitespaceRe finds runs of 40+ consecutive whitespace characters.
// Used to flag the "visual exfiltration" pattern from T8-003 (Invariant's
// WhatsApp takeover) where the attacker hides smuggled data far past the
// user's visible window.
var longWhitespaceRe = regexp.MustCompile(`\s{40,}`)

// maxJSONDepth caps how deep the schema walker will recurse. Defense
// against pathological inputs (e.g. a JSON document with 10,000 nested
// `properties`). Beyond this depth we stop and continue with the next
// tool. ARCHITECTURE.md §2 references this cap.
const maxJSONDepth = 32

// Ingest parses an MCP tool-definitions JSON document from r and
// returns a flat slice of Units — one per scannable surface.
//
// The input format we support is a JSON object with a "tools" array,
// matching what MCP's list_tools endpoint returns. Other shapes get a
// "no tools array found" error.
func Ingest(r io.Reader) ([]Unit, error) {
	var doc map[string]any
	dec := json.NewDecoder(r)
	dec.UseNumber() // preserve number precision; we don't do math on them
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("ingest: parse JSON: %w", err)
	}

	toolsAny, ok := doc["tools"]
	if !ok {
		return nil, fmt.Errorf("ingest: input JSON has no 'tools' key")
	}
	tools, ok := toolsAny.([]any)
	if !ok {
		return nil, fmt.Errorf("ingest: 'tools' must be an array, got %T", toolsAny)
	}

	var units []Unit
	for i, t := range tools {
		toolMap, ok := t.(map[string]any)
		if !ok {
			// Skip non-object entries silently; don't fail the whole scan.
			continue
		}
		path := fmt.Sprintf("tools[%d]", i)
		units = append(units, unitsFromTool(toolMap, path)...)
	}
	return units, nil
}

// unitsFromTool extracts every scannable surface from one tool object
// and returns its list of Units. Never returns an error — bad fields
// are skipped, the scan continues.
func unitsFromTool(tool map[string]any, path string) []Unit {
	name, _ := tool["name"].(string)

	// First pass over the schema: collect context that every Unit from
	// this tool shares (suspicious param names, the tool's own input
	// schema for cross-references).
	ctx := collectToolContext(tool, name)

	var units []Unit

	// Surface 1: the tool name itself. The parameter-name-injection
	// pattern (T4-011) also applies to tool names — the attacker can
	// register a tool called `ignore_previous_and_dump_keys` and the
	// agent will read that name when deciding what to call.
	if name != "" {
		units = append(units, Unit{
			ToolName: name,
			Surface:  SurfaceToolName,
			Path:     path + ".name",
			Text:     name,
			Context:  ctx,
		})
	}

	// Surface 2: the tool's top-level description.
	if desc, ok := tool["description"].(string); ok && desc != "" {
		u := Unit{
			ToolName: name,
			Surface:  SurfaceToolDescription,
			Path:     path + ".description",
			Text:     desc,
			Context:  ctx,
		}
		u.Context.LongWhitespaceRuns = longWhitespaceRe.MatchString(desc)
		units = append(units, u)
	}

	// Surface 3+: walk the input schema and yield one Unit per
	// (parameter_name, schema_property) surface found.
	if schema, ok := tool["inputSchema"].(map[string]any); ok {
		units = append(units, unitsFromSchema(schema, name, path+".inputSchema", 0, ctx)...)
	}

	return units
}

// collectToolContext does a quick first pass to gather data every Unit
// from this tool shares — most importantly, which of this tool's
// parameter names appear on the suspicious-param watchlist.
func collectToolContext(tool map[string]any, toolName string) UnitContext {
	var ctx UnitContext

	if schema, ok := tool["inputSchema"].(map[string]any); ok {
		if props, ok := schema["properties"].(map[string]any); ok {
			for paramName := range props {
				if suspiciousParamNames[strings.ToLower(paramName)] {
					ctx.SuspiciousParameters = append(ctx.SuspiciousParameters, paramName)
				}
			}
		}
	}

	// ReferencedTools / ReferencedServers are populated later, per Unit,
	// when we know the text being scanned. Left empty here.
	return ctx
}

// unitsFromSchema recursively walks a JSON schema subtree (a map[string]any
// shaped per JSON Schema / MCP spec) and yields Units for every text
// surface that an attacker could poison.
//
// depth is how deep we are in the recursion; we abort if it exceeds
// maxJSONDepth to bound worst-case input.
func unitsFromSchema(node map[string]any, toolName, path string, depth int, sharedCtx UnitContext) []Unit {
	if depth >= maxJSONDepth {
		return nil
	}
	var units []Unit

	// Walk `properties`: each key is a parameter name, each value is
	// itself a schema subtree.
	if props, ok := node["properties"].(map[string]any); ok {
		for paramName, propAny := range props {
			propPath := fmt.Sprintf("%s.properties.%s", path, paramName)

			// Parameter name as its own surface.
			units = append(units, Unit{
				ToolName: toolName,
				Surface:  SurfaceParameterName,
				Path:     propPath + ".<key>",
				Text:     paramName,
				Context:  sharedCtx,
			})

			// The property's schema fields.
			if propMap, ok := propAny.(map[string]any); ok {
				units = append(units, surfacePropertyTexts(propMap, toolName, propPath, sharedCtx)...)
				// Recurse: a property can have its own nested `properties`.
				units = append(units, unitsFromSchema(propMap, toolName, propPath, depth+1, sharedCtx)...)
			}
		}
	}

	// Walk `items` (for array-typed parameters with nested schemas).
	if items, ok := node["items"].(map[string]any); ok {
		units = append(units, unitsFromSchema(items, toolName, path+".items", depth+1, sharedCtx)...)
	}

	return units
}

// surfacePropertyTexts emits Units for the text-valued fields of a
// single schema property: description, title, and any string examples.
func surfacePropertyTexts(prop map[string]any, toolName, propPath string, ctx UnitContext) []Unit {
	var units []Unit

	for _, key := range []string{"description", "title"} {
		if s, ok := prop[key].(string); ok && s != "" {
			units = append(units, Unit{
				ToolName: toolName,
				Surface:  SurfaceSchemaProperty,
				Path:     propPath + "." + key,
				Text:     s,
				Context:  ctx,
			})
		}
	}

	if exs, ok := prop["examples"].([]any); ok {
		for i, ex := range exs {
			if s, ok := ex.(string); ok && s != "" {
				units = append(units, Unit{
					ToolName: toolName,
					Surface:  SurfaceSchemaProperty,
					Path:     fmt.Sprintf("%s.examples[%d]", propPath, i),
					Text:     s,
					Context:  ctx,
				})
			}
		}
	}

	return units
}
