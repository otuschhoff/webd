package app

import (
	"encoding/json"
	"fmt"
	"sync"

	gjsonschema "github.com/google/jsonschema-go/jsonschema"
)

const sourceConfigSchemaJSON = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "additionalProperties": false,
  "required": ["routes"],
  "properties": {
    "routes": {
      "type": "array",
      "minItems": 1,
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["path"],
        "properties": {
          "path": {
            "type": "string",
            "pattern": "^(/.*)?$"
          },
          "handler": {
            "type": "string",
            "minLength": 1
          },
          "websocket": {
            "anyOf": [
              {"type": "string", "minLength": 1},
              {"type": "boolean", "enum": [false]}
            ]
          },
          "rewrite_location": {
            "type": "object",
            "additionalProperties": false,
            "required": ["match", "replace"],
            "properties": {
              "match": {
                "type": "string",
                "minLength": 1
              },
              "replace": {
                "type": "string"
              }
            }
          },
          "rewrite_base_href": {
            "type": "boolean"
          },
          "redirect": {
            "type": "string",
            "pattern": "^[A-Za-z][A-Za-z0-9+.-]*://.+"
          },
          "allowed_ipv4": {
            "type": "array",
            "items": {
              "type": "string",
              "minLength": 1
            }
          },
          "browse": {
            "type": "boolean"
          },
          "insecure": {
            "type": "boolean"
          },
          "trusted_ca": {
            "type": "object",
            "additionalProperties": false,
            "required": ["name", "cert_path"],
            "properties": {
              "name": {
                "type": "string",
                "minLength": 1
              },
              "cert_path": {
                "type": "string",
                "minLength": 1
              }
            }
          }
        },
        "oneOf": [
          {
            "required": ["handler"],
            "not": {
              "required": ["redirect"]
            }
          },
          {
            "required": ["redirect"],
            "not": {
              "required": ["handler"]
            }
          }
        ]
      }
    },
    "templates": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "ipv4": {
          "type": "object",
          "additionalProperties": {
            "type": "array",
            "minItems": 1,
            "items": {
              "type": "string",
              "minLength": 1
            }
          }
        },
        "handler": {
          "type": "object",
          "additionalProperties": {
            "type": "string",
            "minLength": 1
          }
        }
      }
    }
  }
}`

const runtimeConfigSchemaJSON = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "additionalProperties": false,
  "required": ["routes"],
  "properties": {
    "routes": {
      "type": "array",
      "minItems": 1,
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["path"],
        "properties": {
          "path": {
            "type": "string",
            "pattern": "^(/.*)?$"
          },
          "allowed_ipv4_ranges": {
            "type": "array",
            "items": {
              "type": "object",
              "additionalProperties": false,
              "required": ["start", "end"],
              "properties": {
                "start": {
                  "type": "integer",
                  "minimum": 0,
                  "maximum": 4294967295
                },
                "end": {
                  "type": "integer",
                  "minimum": 0,
                  "maximum": 4294967295
                }
              }
            }
          },
          "browse": {
            "type": "boolean"
          },
          "redirect": {
            "type": "string",
            "pattern": "^[A-Za-z][A-Za-z0-9+.-]*://.+"
          },
          "websocket_handler": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
              "protocol": {
                "type": "string",
                "enum": ["http", "https", "ws", "wss"]
              },
              "hostname": {
                "type": "string",
                "minLength": 1
              },
              "port": {
                "type": "integer",
                "minimum": 1,
                "maximum": 65535
              },
              "path": {
                "type": "string",
                "pattern": "^/.*"
              },
              "raw_query": {
                "type": "string"
              },
              "ipv4_addresses": {
                "type": "array",
                "minItems": 1,
                "items": {
                  "type": "string",
                  "minLength": 1
                }
              },
              "trusted_ca": {
                "type": "object",
                "additionalProperties": false,
                "required": ["name", "file"],
                "properties": {
                  "name": {
                    "type": "string",
                    "minLength": 1
                  },
                  "file": {
                    "type": "string",
                    "minLength": 1
                  },
                  "pin_cert": {
                    "type": "boolean"
                  }
                }
              }
            },
            "required": ["protocol", "hostname", "port", "ipv4_addresses"]
          },
          "rewrite_location": {
            "type": "object",
            "additionalProperties": false,
            "required": ["match", "replace"],
            "properties": {
              "match": {
                "type": "string",
                "minLength": 1
              },
              "replace": {
                "type": "string"
              }
            }
          },
          "rewrite_base_href": {
            "type": "boolean"
          },
          "handler": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
              "protocol": {
                "type": "string",
                "enum": ["http", "https", "ws", "wss", "file"]
              },
              "hostname": {
                "type": "string",
                "minLength": 1
              },
              "port": {
                "type": "integer",
                "minimum": 1,
                "maximum": 65535
              },
              "path": {
                "type": "string",
                "pattern": "^/.*"
              },
              "raw_query": {
                "type": "string"
              },
              "ipv4_addresses": {
                "type": "array",
                "minItems": 1,
                "items": {
                  "type": "string",
                  "minLength": 1
                }
              },
              "trusted_ca": {
                "type": "object",
                "additionalProperties": false,
                "required": ["name", "file"],
                "properties": {
                  "name": {
                    "type": "string",
                    "minLength": 1
                  },
                  "file": {
                    "type": "string",
                    "minLength": 1
                  },
                  "pin_cert": {
                    "type": "boolean"
                  }
                }
              }
            },
            "oneOf": [
              {
                "required": ["protocol", "hostname", "port", "ipv4_addresses"],
                "properties": {
                  "protocol": {
                    "enum": ["http", "https", "ws", "wss"]
                  }
                }
              },
              {
                "required": ["protocol", "path"],
                "properties": {
                  "protocol": {
                    "const": "file"
                  }
                }
              }
            ]
          }
        },
        "oneOf": [
          {
            "required": ["handler"],
            "not": {
              "required": ["redirect"]
            }
          },
          {
            "required": ["redirect"],
            "not": {
              "required": ["handler"]
            }
          }
        ]
      }
    }
  }
}`

var (
	sourceOnce sync.Once
	sourceRS   *gjsonschema.Resolved
	sourceErr  error

	runtimeOnce sync.Once
	runtimeRS   *gjsonschema.Resolved
	runtimeErr  error
)

func ValidateSourceConfig(instance any) error {
	rs, err := sourceResolved()
	if err != nil {
		return err
	}
	normalized, err := normalizeSchemaInstance(instance)
	if err != nil {
		return fmt.Errorf("normalize source config for schema validation: %w", err)
	}
	if err := rs.Validate(normalized); err != nil {
		return fmt.Errorf("source config schema validation failed: %w", err)
	}
	return nil
}

func ValidateRuntimeConfig(instance any) error {
	rs, err := runtimeResolved()
	if err != nil {
		return err
	}
	normalized, err := normalizeSchemaInstance(instance)
	if err != nil {
		return fmt.Errorf("normalize runtime config for schema validation: %w", err)
	}
	if err := rs.Validate(normalized); err != nil {
		return fmt.Errorf("runtime config schema validation failed: %w", err)
	}
	return nil
}

// jsonschema-go validates JSON-typed values. Marshal/unmarshal coerces structs
// into map/slice/scalar forms accepted by the validator.
func normalizeSchemaInstance(instance any) (any, error) {
	if instance == nil {
		return nil, nil
	}
	b, err := json.Marshal(instance)
	if err != nil {
		return nil, err
	}
	var normalized any
	if err := json.Unmarshal(b, &normalized); err != nil {
		return nil, err
	}
	return normalized, nil
}

func sourceResolved() (*gjsonschema.Resolved, error) {
	sourceOnce.Do(func() {
		sourceRS, sourceErr = resolveSchema(sourceConfigSchemaJSON)
	})
	return sourceRS, sourceErr
}

func runtimeResolved() (*gjsonschema.Resolved, error) {
	runtimeOnce.Do(func() {
		runtimeRS, runtimeErr = resolveSchema(runtimeConfigSchemaJSON)
	})
	return runtimeRS, runtimeErr
}

func resolveSchema(schemaJSON string) (*gjsonschema.Resolved, error) {
	var schema gjsonschema.Schema
	if err := json.Unmarshal([]byte(schemaJSON), &schema); err != nil {
		return nil, fmt.Errorf("parse embedded json schema: %w", err)
	}
	rs, err := schema.Resolve(nil)
	if err != nil {
		return nil, fmt.Errorf("resolve embedded json schema: %w", err)
	}
	return rs, nil
}
