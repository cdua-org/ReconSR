# ReconSR Module Development Guide

## 1. Overview
Modules in the ReconSR automated OSINT tool are independent plugins designed to execute specific data gathering and reconnaissance tasks.

Developing a module does not require knowledge of the core system's architecture or source code. The core system automatically manages task routing, loop prevention, database storage, and type-specific syntax validation. Module developers only need to implement a standard interface and adhere to the data exchange contract defined in the `cdua-org/ReconSR/schema` package.

*Note on Validation:* The core performs structural and syntax validation for known entity types. If a module returns an entity with malformed syntax (e.g., an email or domain containing unsupported characters), the system will automatically flag the result as `invalid` and halt further processing for that specific node.

## 2. Technical Requirements
- **Language:** Go (Golang).
- **Core Package:** `cdua-org/ReconSR/schema`.
- **Dependencies:** Modules must not depend on any internal core packages of the system. All interaction occurs strictly via structures from the `schema` package.

---

## 3. The Module Interface
Every module must implement the `schema.Module` interface:

```go
type Module interface {
	Name() string
	Capabilities() (ModuleCapabilities, error)
	Exec(ModuleInput) (ModuleOutput, error)
}
```

### 3.1 `Name() string`
Returns the unique name of the module (e.g., `"whois"`, `"dns"`, `"subdomain_hierarchy"`).

### 3.2 `Capabilities() (schema.ModuleCapabilities, error)`
Defines the module's capabilities: what functions it provides, what data types it accepts, and establishes concurrency limits and rate-limiting delays to protect against bans.

### 3.3 `Exec(data schema.ModuleInput) (schema.ModuleOutput, error)`
The main execution pipeline.
- **Input (`ModuleInput`):** Contains the `Target` (the entity to analyze) and `Functions` (a list of tasks requested by the core).
- **Output (`ModuleOutput`):** A list of execution results (`Executions`). A single module call can process multiple functions simultaneously.

---

## 4. The Capabilities Contract
ReconSR uses a hierarchical capabilities contract. Configurations can be defined specifically for individual functions, or global defaults can be established for the entire module.
The core resolves properties based on the following priority (highest to lowest): `CustomFunctions` -> `ModuleConfig` -> Base `Functions`/`InputTypes`.

### `FunctionCapabilities` Structure
| Field | Description |
| :--- | :--- |
| `InputTypes` | The entity types this function accepts (e.g., `["domain", "ipv4", "ipv6"]`). Refer to section 4.1. |
| `Limit` | The maximum number of concurrent goroutines allowed for this function. (Note: The core enforces a hard system cap to protect the host; requested limits will be capped to a safe maximum if they are too high). Refer to section 4.2. |
| `DelayMs` | **CRITICAL:** The delay in milliseconds between requests. This serves as the primary defense against IP bans (Rate Limiting) when querying external APIs. If `0` (and not specified elsewhere), it runs without delay. **If a module makes HTTP requests, a delay MUST be specified!** Refer to section 4.2. |
| `RequiredTags` | Advanced execution filtering based on logical conditions (AND, OR, NOT). Refer to section 4.3. |
| `Meta` | Arbitrary data (key-value pairs) for future extensions or experimental flags. |

### 4.1 Input Types and Routing Rules

The `InputTypes` array dictates which entity types (e.g., `["domain", "ipv4"]`) are allowed to be routed to a function. The core resolves these types strictly. It is required to declare `InputTypes` at the correct level to ensure functions are only passed data they can process:

- **Module-Level Routing (Default):** If `InputTypes` is defined at the base level (or within `ModuleConfig`), those types act as the default for all functions in the module. Every function using this default must be capable of processing all the listed types.
- **Function-Level Routing (Override):** If a module-level default is defined, a specific function within `CustomFunctions` can still override it with its own unique `InputTypes`.
- **Function-Level Routing (Explicit):** Module-level defaults can be omitted entirely, defining `InputTypes` strictly for each function within `CustomFunctions`.

**Example A: Module-Level Routing (Shared Types)**
Every function in this module is capable of processing both domains and subdomains. If types are shared, the function names and their inputs are simply listed at the base level.
```go
func (m *module) Capabilities() (schema.ModuleCapabilities, error) {
    return schema.ModuleCapabilities{
        Functions:  []string{"dns_a_record", "dns_mx_record"},
        InputTypes: []string{"domain", "subdomain"},
    }, nil
}
```

**Example B: Hybrid Routing (Global Defaults with Specific Override)**
Most functions in the module share the same input types, but one specific function requires a different type. The specific function overrides the global default.
```go
func (m *module) Capabilities() (schema.ModuleCapabilities, error) {
    return schema.ModuleCapabilities{
        // Default types for functions listed in the base array
        Functions:  []string{"get_domain_whois", "get_domain_history"},
        InputTypes: []string{"domain"}, 

        // Specific override for a function requiring different types
        CustomFunctions: map[string]schema.FunctionCapabilities{
            "check_ip_reputation": { 
                InputTypes: []string{"ipv4", "ipv6"}, // Overrides the global "domain" type
            },
        },
    }, nil
}
```

**Example C: Function-Level Routing (No Global Defaults)**
This module has functions designed for different data types. No global `InputTypes` or `Functions` array is defined; everything is explicitly configured within `CustomFunctions`.
```go
func (m *module) Capabilities() (schema.ModuleCapabilities, error) {
    return schema.ModuleCapabilities{
        CustomFunctions: map[string]schema.FunctionCapabilities{
            "check_ip_reputation": { 
                InputTypes: []string{"ipv4", "ipv6"}, 
            },
            "get_domain_whois": { 
                InputTypes: []string{"domain"}, 
            },
        },
    }, nil
}
```

### 4.2 Concurrency and Rate Limiting

Balancing concurrency limits and delays optimizes execution speed while ensuring system stability and preventing service bans. If the majority of a module's functions share the same limits, they can be defined at the module level using `ModuleConfig`. If specific functions require different settings (e.g., a fast local function versus a heavy API query), `CustomFunctions` should be used to override these module-level defaults.

**Important Note on `Limit`:**
- **High Limits (e.g., 1000):** For lightweight local operations (like string parsing) that do not strain system resources.
- **Low Limits (e.g., 5-50):** For resource-intensive functions that consume significant CPU/memory, to prevent overloading the host system.

**Important Note on `DelayMs`:**
- The delay value must be specified in milliseconds (e.g., `1000` for a 1-second delay). When a module interacts with third-party APIs or external services, it must respect the target's specific rate limits. A well-calibrated delay is necessary to prevent overwhelming the remote server, which can result in IP bans (e.g., HTTP 429 Too Many Requests).

**Example: Module-Level Defaults with Specific Overrides**
This example demonstrates setting a default configuration for the module, while explicitly overriding the parameters for specific functions.

```go
func (m *module) Capabilities() (schema.ModuleCapabilities, error) {
    return schema.ModuleCapabilities{
        // 1. Module-Level Defaults (Applied to all functions unless overridden)
        ModuleConfig: &schema.FunctionCapabilities{
            Limit:   5,    // Low limit for resource-intensive functions to prevent host overload
            DelayMs: 1000, // 1-second pause to respect external service rate limits
        },

        // 2. Specific Overrides (Takes priority over ModuleConfig)
        CustomFunctions: map[string]schema.FunctionCapabilities{
            "decompose": {
                Limit:   1000, // High limit because this function is lightweight
                DelayMs: 0,    // Explicitly disable the global delay for local operations
            },
            "heavy_api_query": {
                // Inherits Limit (5) from ModuleConfig but requires a longer delay
                DelayMs: 5000, // 5-second pause to prevent rate limiting
            },
        },
    }, nil
}
```
---

### 4.3 Conditional Filtering and Execution Ordering (`RequiredTags`)

The `RequiredTags` field provides a mechanism for controlling exactly when a function executes. This allows a strict execution order (chaining) to be established between functions and state or success markers to be passed. For instance, Function A can perform a basic check and attach a specific technical tag upon success (e.g., `{".dns_resolved"}`). Function B can then require this tag, ensuring it only runs after Function A has successfully validated the entity.

To implement these conditions, `RequiredTags` utilizes a `[][]string` format evaluated as a logical **OR of ANDs (including NOT)**:
- **Inner arrays** represent tags joined by logical **AND**.
- **Outer arrays** represent conditions joined by logical **OR**.
- **NOT Operator (`!`):** Prefixing a tag with an exclamation mark (`!`) requires the **absence** of that specific tag.

#### Logic Combination Examples

**1. Logical AND (Requires ALL tags)**
*Condition: The entity must possess both `A` AND `B`.*
```go
RequiredTags: [][]string{
    {"A", "B"}, // Needs both A and B simultaneously
}
```

**2. Logical OR (Requires ANY tag)**
*Condition: The entity must possess `A` OR `B`.*
```go
RequiredTags: [][]string{
    {"A"}, // A is sufficient
    {"B"}, // B is sufficient
}
```

**3. Complex Combination: (A AND B) OR C**
*Condition: Needs both `A` AND `B`, OR just `C`.*
```go
RequiredTags: [][]string{
    {"A", "B"}, 
    {"C"},      
}
```

**4. Negative Tag (Exclusion): A AND NOT B**
*Condition: Needs `A`, but MUST NOT possess `B`.*
```go
RequiredTags: [][]string{
    {"A", "!B"}, // Execute if A is present AND B is absent
}
```

**5. Complex Exclusion: (NOT C) OR (A AND B)**
*Condition: Executes if `C` is absent. If `C` is present, still Executes if both `A` and `B` are present.*
```go
RequiredTags: [][]string{
    {"!C"},     
    {"A", "B"}, 
}
```

#### Real-World Scenarios

**Scenario A: Avoiding Unnecessary Work**
Excluding domains known to be parked or dead from scanning.
```go
"heavy_scan": {
    InputTypes: []string{"domain"},
    RequiredTags: [][]string{
        {"!.parked", "!.dead"}, // Execute ONLY if it LACKS both tags
    },
}
```

**Scenario B: Multiple Valid States**
Scanning active web servers on either HTTP or HTTPS.
```go
"web_scan": {
    InputTypes: []string{"domain", "ipv4"},
    RequiredTags: [][]string{
        {".web_active", ".http"},  // Execute if it has BOTH ".web_active" AND ".http"
        {".web_active", ".https"}, // OR if it has BOTH ".web_active" AND ".https"
    },
}
```

---

## 5. Execution and Results (`ModuleExecution` & `ModuleResult`)

For every function requested by the core in `data.Functions`, the module must return exactly one `schema.ModuleExecution` object, which contains an array of `schema.ModuleResult` items.

### 5.1 The `ModuleExecution` Structure (One Function Call)
| Field | Status | Description |
| :--- | :--- | :--- |
| **`Function`** | **Mandatory** | The name of the function executed (must match the requested function). |
| **`Results`** | **Optional** | A slice of discovered `ModuleResult` entities. Can be empty if nothing was found. |
| **`RawData`** | **Conditional** | **Evidence Collection.** The full, unaltered raw response must be provided to preserve OSINT evidence. This applies to any raw data obtained, regardless of whether the data is suitable for processing or represents a reported error. This data is supplied exactly once per function execution, regardless of the number of entities discovered. If no raw data was generated, this field must be omitted. |
| **`Error`** | **Optional** | A pointer to a string. This field must be set ONLY in the event of a technical failure (e.g., network error, bad HTTP status, or parsing failure). It must contain a concise, summarized technical error message (e.g., `err.Error()` or "HTTP 403: API limit exceeded") to facilitate monitoring. Full error response bodies must not be included here; such raw responses must be placed in the `RawData` instead. This field must not be used to indicate the absence of data (e.g., "no results found" is not an error; an empty 'Results' slice must be returned instead). |

**Example A: Successful Execution**
```go
var simulatedError *string = nil 
rawResponse := `{"status": "active", "ip": "192.0.2.1"}`

execSuccess := schema.ModuleExecution{
        Function: "analyze_domain",
        RawData:  rawResponse,
        Error:    simulatedError, 
        Results: []schema.ModuleResult{
                // (Refer to Section 5.2)
        },
}
```

**Example B: Technical Failure**
```go
errMsg := "HTTP 429: Rate Limit Exceeded"
rawResponse := `{"error": "Too many requests", "code": 429}` // Contains the raw error response

execError := schema.ModuleExecution{
        Function: "analyze_domain",
        RawData:  rawResponse,
        Error:    &errMsg, 
        Results:  []schema.ModuleResult{}, 
}
```

### 5.2 The `ModuleResult` Structure (One Discovered Item)
| Field | Status | Description |
| :--- | :--- | :--- |
| **`Type`** | **Mandatory** | The exact entity type. A correct type must be provided; otherwise, the system may mark the entity type as `invalid`. The only exceptions are two specific entity groups where the core system permits interchangeable types: domains (providing `domain` or `subdomain` is interchangeable and will be automatically corrected) and IP addresses (providing `ip`, `ipv4`, or `ipv6` is interchangeable and will be automatically corrected). For all other entities, the provided type must be exact. |
| **`Value`** | **Mandatory** | The extracted value (e.g., `"192.0.2.1"`). While standard extraction is necessary, syntactic errors within the entity itself must not be auto-corrected or cleaned. Malformed data must be preserved exactly as found to allow analysts to identify real-world configuration errors. If a function identifies a malformed entity but can infer the intended correct value, it may return both: the malformed entity as the primary finding, and the corrected entity linked to the malformed one via the `Source` field (Refer to Section 5.3). |
| **`Category`**| **Optional** | Controls visual representation on the graph UI. `"node"` (default) renders as a standalone, connectable entity. `"property"` renders as an attribute within the parent node's modal window (e.g., a DMARC record or ASN). Note: This does not affect data processing; further modules can process both nodes and properties equally. |
| **`Context`** | **Optional** | A human-readable description of the semantic relationship between the source and the discovered entity (e.g., specifying if an extracted email is a "rua reporting address" or an "admin contact"). This field must not be used for technical debugging details. If the relationship is already obvious from the entity's `Type`, this field must be omitted to prevent redundant UI labels (e.g., writing "DMARC Record" for a `dmarc` type). |
| **`Tags`** | **Optional** | An array of tags to assign to the entity. **Format Constraint:** Tags must consist only of the characters `a-z0-9_.-`. Providing a malformed tag will cause the core system to reject the result and generate a function error.<br><br>**Technical Tags (Prefixed with `.`):** Tags starting with a dot (e.g., `.dns_resolved`) are strictly for internal system use, such as inter-function routing and establishing execution order (Refer to Section 4.3). These technical tags are completely invisible to the user. Multiple tags can be assigned simultaneously, but they must be restricted to those explicitly expected by other functions.<br><br>**Display Tags (No Prefix):** Tags that do not start with a dot are treated as user-facing "subtypes". They are displayed to the user in the UI as supplementary information alongside the primary entity type. |
| **`Applied`** | **Optional** | (Defaults to `false`). If `true`, instructs the core not to execute the current function on this specific result again. This prevents redundant reprocessing of results (e.g., when a function decomposes a long subdomain like `a.b.c.com` into `b.c.com` and `c.com`, setting `Applied` ensures the function is not re-run on those extracted parts). |
| **`OutOfScope`**| **Optional** | (Defaults to `false`). If `true`, instructs the core to record the result in the database (for visual graphing) but to exclude it from being routed to modules to discover new relationships. Useful for filtering out "noise" infrastructure (e.g., registrar domains, CDN IPs). |
| **`Source`** | **Optional** | A pointer to `schema.EntityRef{Type, Value}`. Specifies the immediate parent of the discovered entity. This is used when a function discovers a sequential chain of relationships (e.g., Target -> Property -> Node) rather than a flat "star" topology radiating directly from the input target. If the finding connects directly to the input target, this field must be omitted. Detailed chaining patterns are covered in Section 5.3. |

**Examples: Discovered Entities**
```go
// Simulated values extracted during function execution
parsedDomain := "example.com"
nodeIP := "192.0.2.2"

results := []schema.ModuleResult{
        {
                Type:     "domain",
                Value:    parsedDomain,
                Category: "node", // Default value, shown for clarity
                Context:  "Related organizational domain",
                Tags:     []string{".verified"},
                Applied:  true,
        },
        {
                Type:       "ip",
                Value:      nodeIP,
                Context:    "Infrastructure IP",
                OutOfScope: true, 
        },
}
```

---

### 5.3 Graph Relationships and Chaining (`Source`)

By default, the core links every item in `Results` directly to the initial `Target`, creating a flat "star" topology. If this is the intended relationship, the `Source` field must be omitted.

When a module discovers data that forms sequential chains (e.g., `Target` -> `Intermediate Node` -> `Final Node`), the immediate parent of the discovered entity must be explicitly specified using the `Source` field (`*schema.EntityRef{Type, Value}`). 

The core validates all graph connections. An entity can be specified as a `Source` only if it is also declared as a discovered result elsewhere within the exact same `exec.Results` slice. When defining a `Source`, only its `Type` and `Value` must be specified. These two fields must match the `Type` and `Value` of that exact same entity where it was declared as a discovered result. All other fields (e.g., context, tags, category, out_of_scope) are assigned exclusively when declaring an entity as a result, never when referencing it as a source. Every discovered entity within the `exec.Results` slice must trace back to the module's input target through a continuous chain of declared relationships. Any break in this chain creates an isolated graph "island", and all entities of such an "island" are marked by the core as `invalid`.

#### Pattern 1: Node-to-Node Decomposition
To represent a chain of derived entities (e.g., breaking a subdomain into parent domains), each intermediate entity must be explicitly assigned as the `Source` for the next entity in the chain.
```go
// Input Target: a.b.c.com
// Chain: a.b.c.com -> b.c.com -> c.com

// 1. Return the first intermediate subdomain (defaults to linking to input Target)
exec.Results = append(exec.Results, schema.ModuleResult{
    Type:    "subdomain",
    Value:   "b.c.com",
    Context: "Parent subdomain",
    Applied: true, // Prevents re-running decompose on b.c.com
})

// 2. Return the next domain, linking it sequentially to the intermediate finding
exec.Results = append(exec.Results, schema.ModuleResult{
    Type:    "domain",
    Value:   "c.com",
    Context: "Organizational domain",
    Source: &schema.EntityRef{
        Type:  "subdomain",
        Value: "b.c.com", // Exact match with step 1
    },
})
```

#### Pattern 2: Property-to-Node Enrichment
Entities of category `node` extracted from an entity of category `property` must explicitly reference the `property` entity as their `Source`.
```go
// 1. Return the DMARC record (category: property). Links to the original Target by default.
exec.Results = append(exec.Results, schema.ModuleResult{
    Type:     "dmarc",
    Category: "property",
    Value:    "v=DMARC1; p=reject; rua=mailto:admin@example.com",
    // Context omitted: Redundant due to 'dmarc' type
})

// 2. Return the extracted email (category: node), explicitly specifying the DMARC record from step 1 as its Source.
exec.Results = append(exec.Results, schema.ModuleResult{
    Type:     "email",
    Category: "node", // Default category, explicitly shown here for clarity
    Value:    "admin@example.com",
    Context:  "Rua reporting address",
    Source: &schema.EntityRef{
        Type:  "dmarc",
        Value: "v=DMARC1; p=reject; rua=mailto:admin@example.com", // Exact match with step 1
    },
})
```

#### Pattern 3: Syntax Correction Pattern (Dual Return)
As mandated in Section 5.2, malformed syntax must not be cleaned from the primary finding. If a corrected entity is additionally returned, it must explicitly reference the malformed entity as its `Source`.
```go
// Original data from server: 'admin@example.com)' (contains a trailing bracket)

// 1. Return the malformed data exactly as found (evidence)
exec.Results = append(exec.Results, schema.ModuleResult{
    Type:  "email",
    Value: "admin@example.com)",
    Context: "Admin email",
})

// 2. Return the cleaned data, linking it to the malformed evidence
exec.Results = append(exec.Results, schema.ModuleResult{
    Type:  "email",
    Value: "admin@example.com",
    Context: "Admin email",
    Source: &schema.EntityRef{
        Type:  "email",
        Value: "admin@example.com)", // Exact match with step 1
    },
})
```

---

## 6. Implementation Rules

1. **Strict Execution Contract:** Modules must return exactly one `ModuleExecution` object for every function requested in `data.Functions`, even if the result is empty or an error occurred. Returning data for unrequested functions will result in a contract violation error.
2. **Mandatory Evidence Collection (`RawData`):** If a function queries an external service, the full raw text response must be preserved. This rule applies equally to successful extractions and raw error responses.
3. **Automatic Target Filtering:** The original input `Target` is automatically filtered out by the core system if it is returned within the results. The input target is only processed if the returned entity features a modified `Type` or introduces new `Tags`.
4. **Concise Errors (`Error`):** The `Error` field must contain a short, summarized technical error message (e.g., `err.Error()` or "HTTP 500: Server Error"). Large HTML/JSON response bodies must not be included here; they belong in the `RawData` field.
5. **Graph Integrity:** When a module returns a chain of discovered entities within an `exec.Results` slice, every entity in that specific slice must trace back to the module's input target through a continuous chain of `Source` declarations. Entities forming disconnected islands within the slice will be marked as `invalid` by the core.
6. **Tag Discipline (`Tags`):** Tags are invisible to the researcher and serve purely as internal routing triggers. Tags must not be assigned arbitrarily. A tag must only be assigned if another function in the system explicitly requires it for execution. Conversely, a function must only require a tag if it is known that another function assigns it.

---

## 7. Basic Module Example

The following template demonstrates how to implement the module interface and return a standard flat result.

```go
package example_module

import (
	"cdua-org/ReconSR/schema"
)

type module struct{}

// New instantiates the module for registration.
func New() schema.Module { return &module{} }

func (m *module) Name() string { return "basic_module" }

func (m *module) Capabilities() (schema.ModuleCapabilities, error) {
	return schema.ModuleCapabilities{
		// Configuration for the module
		ModuleConfig: &schema.FunctionCapabilities{
			Limit:      5,
			DelayMs:    1000,
			InputTypes: []string{"domain"},
		},
		Functions: []string{"basic_function"},
	}, nil
}

func (m *module) Exec(data schema.ModuleInput) (schema.ModuleOutput, error) {
	executions := make([]schema.ModuleExecution, 0, len(data.Functions))

	for _, f := range data.Functions {
		exec := schema.ModuleExecution{Function: f}

		switch f {
		case "basic_function":
			// 1. Custom logic (e.g., network query, string parsing) is implemented here
			// For this example, variables obtained from an external query are simulated:
			simulatedRawData := "Domain: example.org\nIP: 192.0.2.1\nEmail: admin@example.org"
			var simulatedError *string = nil // Must be set to a string pointer if a technical error occurs (e.g., &errStr)

			// Simulated parsed findings:
			discoveredDomain := "example.org"
			domainType := "domain"
			domainContext := "Related domain"

			discoveredIP := "192.0.2.1"
			ipType := "ip" // The core automatically corrects 'ip' to 'ipv4' or 'ipv6'
			ipContext := "Resolved IP address"

			discoveredEmail := "admin@example.org"
			emailType := "email"
			emailContext := "Admin contact"

			// 2. Unaltered evidence (if received) must be saved
			// This must be done even if an HTTP error occurred, to preserve the error response body.
			if simulatedRawData != "" {
				exec.RawData = simulatedRawData
			}

			// 3. Technical error handling (if occurred)
			if simulatedError != nil {
				exec.Error = simulatedError
				break // Halting entity processing for this function, while RawData remains saved
			}

			// 4. Appending discovered entities conditionally using dynamic variables
			if discoveredDomain != "" {
				exec.Results = append(exec.Results, schema.ModuleResult{
					Type:    domainType,
					Value:   discoveredDomain,
					Context: domainContext,
				})
			}

			if discoveredIP != "" {
				exec.Results = append(exec.Results, schema.ModuleResult{
					Type:    ipType,
					Value:   discoveredIP,
					Context: ipContext,
				})
			}

			if discoveredEmail != "" {
				exec.Results = append(exec.Results, schema.ModuleResult{
					Type:    emailType,
					Value:   discoveredEmail,
					Context: emailContext,
				})
			}

		}

		executions = append(executions, exec)
	}

	return schema.ModuleOutput{Executions: executions}, nil
}
```

---

## 8. Module Registration

ReconSR utilizes static registration for its modules. A module must be explicitly registered with the system dispatcher to be included in the execution loop.

To register a new module:
1. Open the core registry file: `internal/dispatcher/registry.go`.
2. Import the new module's package.
3. Instantiate and append the module to the `ModuleRegistry` slice.

**Example Registration:**
```go
package dispatcher

import (
        // ... existing imports ...
        "cdua-org/ReconSR/modules/example_module"
)

// ...

var ModuleRegistry = []schema.Module{
        // ... existing modules ...
        example_module.New(),
}
```
