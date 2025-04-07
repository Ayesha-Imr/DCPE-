/**
 * Base adapter interface for vector databases
 * This is an abstract class that should be extended to create specific database adapters.
 * It provides a standard interface for interacting with different vector databases,
 * allowing DCPE to work with any vector database that implements this interface.
 * 
 * @example
 * ```javascript
 * import { BaseAdapter } from 'dcpe-js';
 * 
 * class PineconeAdapter extends BaseAdapter {
 *   constructor(config) {
 *     super(config);
 *     this.client = null;
 *   }
 * 
 *   async connect() {
 *     // Implement connection to Pinecone
 *   }
 *   
 *   // Implement other required methods...
 * }
 * ```
 */
class BaseAdapter {
  /**
   * Create a new adapter instance
   * @param {Object} config - Configuration options
   * @param {string} [config.host] - Database host URL
   * @param {string} [config.apiKey] - API key for authentication
   * @param {string} [config.collectionName] - Collection/index name
   * @param {number} [config.dimension] - Vector dimension
   * @param {string} [config.metricType="cosine"] - Distance metric type (cosine, euclidean, dot)
   */
  constructor(config = {}) {
    this.config = config;
  }

  /**
   * Connect to the vector database
   * Implementations should establish a connection to the database
   * and prepare any necessary resources (create collections, etc.)
   * 
   * @returns {Promise<boolean>} - True if connection was successful
   * @throws {Error} - If connection fails
   * 
   * @example
   * ```javascript
   * const adapter = new CustomAdapter({ host: 'https://db.example.com', apiKey: 'key123' });
   * await adapter.connect();
   * ```
   */
  async connect() {
    throw new Error('Method not implemented: connect');
  }

  /**
   * Disconnect from the vector database
   * Implementations should clean up resources and close connections
   * 
   * @returns {Promise<void>}
   * @throws {Error} - If disconnection fails
   * 
   * @example
   * ```javascript
   * await adapter.disconnect();
   * ```
   */
  async disconnect() {
    throw new Error('Method not implemented: disconnect');
  }

  /**
   * Insert vectors into the database
   * @param {Array<Object>} vectors - Vectors to insert
   * @param {string} [vectors[].id] - Optional unique identifier for the vector
   * @param {Array<number>} vectors[].vector - The vector embedding to insert
   * @param {Object} [vectors[].metadata] - Optional metadata associated with the vector
   * @returns {Promise<Array<string>>} - IDs of the inserted vectors
   * @throws {Error} - If insertion fails
   * 
   * @example
   * ```javascript
   * const vectors = [
   *   { id: 'doc1', vector: [0.1, 0.2, 0.3], metadata: { text: 'encrypted text', category: 'encrypted category' }},
   *   { id: 'doc2', vector: [0.4, 0.5, 0.6], metadata: { text: 'encrypted text', category: 'encrypted category' }}
   * ];
   * const ids = await adapter.insert(vectors);
   * ```
   */
  async insert(vectors) {
    throw new Error('Method not implemented: insert');
  }

  /**
   * Search for vectors in the database
   * @param {Array<number>} queryVector - Query vector to search for
   * @param {Object} options - Search options
   * @param {number} [options.limit=10] - Maximum number of results to return
   * @param {number} [options.threshold=0.7] - Similarity threshold (database-specific implementation)
   * @param {Object} [options.filter] - Filter conditions for metadata (database-specific implementation)
   * @returns {Promise<Array<Object>>} - Search results with format [{ id, vector, metadata, score/distance }]
   * @throws {Error} - If search fails
   * 
   * @example
   * ```javascript
   * const queryVector = [0.1, 0.2, 0.3];
   * const results = await adapter.search(queryVector, { 
   *   limit: 5, 
   *   filter: { category: encryptedCategoryValue } 
   * });
   * ```
   */
  async search(queryVector, options = {}) {
    throw new Error('Method not implemented: search');
  }
}

export default BaseAdapter;