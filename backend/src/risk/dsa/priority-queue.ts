/**
 * SentinelX Milestone 2.4 - Binary Heap Priority Queue
 * 
 * Provides an optimal O(log N) Priority Queue for incident prioritization and
 * an O(N log K) Top-K selection algorithm with O(K) auxiliary space.
 */

export type HeapType = 'MAX' | 'MIN';

export interface HeapNode<T> {
  item: T;
  priority: number;
  sequence: number; // Monotonic sequence for deterministic FIFO tie-breaking
}

export class RiskPriorityQueue<T> {
  private heap: HeapNode<T>[] = [];
  private sequenceCounter = 0;
  private readonly isMaxHeap: boolean;

  constructor(type: HeapType = 'MAX') {
    this.isMaxHeap = type === 'MAX';
  }

  /**
   * Compares two nodes based on heap type and sequence for tie-breaking.
   * In MAX-HEAP: returns true if a has higher priority than b (or earlier sequence on tie).
   * In MIN-HEAP: returns true if a has lower priority than b (or earlier sequence on tie).
   */
  private compare(a: HeapNode<T>, b: HeapNode<T>): boolean {
    if (a.priority !== b.priority) {
      return this.isMaxHeap ? a.priority > b.priority : a.priority < b.priority;
    }
    // Tie-breaker: earlier sequence preferred (FIFO)
    return a.sequence < b.sequence;
  }

  /**
   * Inserts an item with a priority into the binary heap.
   * Time Complexity: O(log N)
   * Space Complexity: O(1) amortized
   */
  insert(item: T, priority: number): void {
    const node: HeapNode<T> = {
      item,
      priority,
      sequence: ++this.sequenceCounter,
    };
    this.heap.push(node);
    this.bubbleUp(this.heap.length - 1);
  }

  /**
   * Extracts and returns the highest-priority element (in Max-Heap) or lowest (in Min-Heap).
   * Time Complexity: O(log N)
   * Space Complexity: O(1)
   */
  extract(): T | undefined {
    if (this.heap.length === 0) return undefined;
    if (this.heap.length === 1) return this.heap.pop()!.item;

    const root = this.heap[0].item;
    this.heap[0] = this.heap.pop()!;
    this.bubbleDown(0);
    return root;
  }

  /**
   * Returns the root item without removing it.
   * Time Complexity: O(1)
   */
  peek(): T | undefined {
    return this.heap.length > 0 ? this.heap[0].item : undefined;
  }

  /**
   * Returns the priority value of the root item without removing it.
   * Time Complexity: O(1)
   */
  peekPriority(): number | undefined {
    return this.heap.length > 0 ? this.heap[0].priority : undefined;
  }

  /**
   * Current number of elements in the heap.
   * Time Complexity: O(1)
   */
  size(): number {
    return this.heap.length;
  }

  /**
   * Checks if heap is empty.
   * Time Complexity: O(1)
   */
  isEmpty(): boolean {
    return this.heap.length === 0;
  }

  /**
   * Empties the priority queue.
   */
  clear(): void {
    this.heap = [];
    this.sequenceCounter = 0;
  }

  /**
   * Returns an unordered shallow copy of all items in the queue.
   */
  toArray(): T[] {
    return this.heap.map((node) => node.item);
  }

  /**
   * Drains the queue in descending priority order (or ascending if Min-Heap).
   * Time Complexity: O(N log N)
   */
  drainSorted(): T[] {
    const sorted: T[] = [];
    while (!this.isEmpty()) {
      sorted.push(this.extract()!);
    }
    return sorted;
  }

  private bubbleUp(index: number): void {
    while (index > 0) {
      const parentIndex = Math.floor((index - 1) / 2);
      if (this.compare(this.heap[index], this.heap[parentIndex])) {
        // Swap
        const temp = this.heap[index];
        this.heap[index] = this.heap[parentIndex];
        this.heap[parentIndex] = temp;
        index = parentIndex;
      } else {
        break;
      }
    }
  }

  private bubbleDown(index: number): void {
    const length = this.heap.length;
    while (true) {
      let candidateIndex = index;
      const leftChild = 2 * index + 1;
      const rightChild = 2 * index + 2;

      if (
        leftChild < length &&
        this.compare(this.heap[leftChild], this.heap[candidateIndex])
      ) {
        candidateIndex = leftChild;
      }

      if (
        rightChild < length &&
        this.compare(this.heap[rightChild], this.heap[candidateIndex])
      ) {
        candidateIndex = rightChild;
      }

      if (candidateIndex !== index) {
        const temp = this.heap[index];
        this.heap[index] = this.heap[candidateIndex];
        this.heap[candidateIndex] = temp;
        index = candidateIndex;
      } else {
        break;
      }
    }
  }

  /**
   * Selects Top-K highest priority items from an input stream/array using a bounded Min-Heap of size K.
   * 
   * Algorithmic Guarantee:
   * - Time Complexity: O(N log K)
   * - Space Complexity: O(K) auxiliary
   * 
   * When K << N (e.g. top 20 out of 50,000 items), this is substantially faster than O(N log N) full sorting.
   */
  static topK<T>(items: Array<{ item: T; priority: number }>, k: number): T[] {
    if (!items || items.length === 0 || k <= 0) return [];
    if (k >= items.length) {
      // If K >= N, sort directly
      return [...items]
        .sort((a, b) => b.priority - a.priority)
        .map((x) => x.item);
    }

    // Min-Heap of capacity K to track the K highest elements
    const minHeap = new RiskPriorityQueue<T>('MIN');

    for (const entry of items) {
      if (minHeap.size() < k) {
        minHeap.insert(entry.item, entry.priority);
      } else if (entry.priority > minHeap.peekPriority()!) {
        minHeap.extract(); // Evict smallest of the top-K
        minHeap.insert(entry.item, entry.priority);
      }
    }

    // Draining Min-Heap gives items ascending; reverse to get descending order
    const result = minHeap.drainSorted();
    return result.reverse();
  }
}
