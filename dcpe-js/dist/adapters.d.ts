/**
 * Type definitions for DCPE-JS vector database adapters
 */

/**
 * Base adapter interface for vector databases
 * This is an abstract class that should be extended to create specific database adapters
 */
export class BaseAdapter {
  /**
   * Create a new adapter instance
   * @param config - Configuration options
   */
  constructor(config?: {
    host?: string;
    apiKey?: string;
    collectionName?: string;
    dimension?: number;
    metricType?: string;
    [key: string]: any;
  });

  /**
   * Connect to the vector database
   */
  connect(): Promise<boolean>;

  /**
   * Disconnect from the vector database
   */
  disconnect(): Promise<void>;

  /**
   * Insert vectors into the database
   * @param vectors - Vectors to insert
   */
  insert(vectors: Array<{
    id?: string;
    vector: number[];
    metadata?: Record<string, any>;
  }>): Promise<string[]>;

  /**
   * Search for vectors in the database
   * @param queryVector - Query vector
   * @param options - Search options
   */
  search(queryVector: number[], options?: {
    limit?: number;
    threshold?: number;
    filter?: Record<string, any>;
    [key: string]: any;
  }): Promise<Array<{
    id: string;
    vector?: number[];
    metadata?: Record<string, any>;
    score?: number;
    distance?: number;
  }>>;
}