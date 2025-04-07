/**
 * Validate configuration object against schema
 * @param {Object} config - Configuration to validate
 * @param {Object} schema - Schema definition
 * @returns {Object} - Validated configuration with defaults
 */
export function validateConfig(config, schema) {
    const result = { ...config };
    const errors = [];
  
    // Check required fields
    if (schema.required) {
      for (const field of schema.required) {
        if (result[field] === undefined) {
          errors.push(`Missing required field: ${field}`);
        }
      }
    }
  
    // Apply defaults
    if (schema.properties) {
      for (const [key, prop] of Object.entries(schema.properties)) {
        if (result[key] === undefined && prop.default !== undefined) {
          result[key] = prop.default;
        }
        
        // Type validation
        if (result[key] !== undefined && prop.type) {
          const type = typeof result[key];
          if (type !== prop.type) {
            errors.push(`Type mismatch for ${key}: expected ${prop.type}, got ${type}`);
          }
        }
      }
    }
  
    if (errors.length > 0) {
      throw new Error(`Configuration validation failed: ${errors.join(', ')}`);
    }
  
    return result;
  }
  
  /**
   * Create a schema for configuration validation
   * @param {Object} properties - Schema properties
   * @param {Array<string>} required - Required field names
   * @returns {Object} - Schema definition
   */
  export function createSchema(properties, required = []) {
    return {
      properties,
      required
    };
  }