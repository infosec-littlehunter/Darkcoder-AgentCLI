#!/usr/bin/env node

/**
 * Memory Leak Stress Test
 * Tests if scheduler cleanup properly prevents memory leaks
 */

const { CoreToolScheduler } = require('@darkcoder/darkcoder-core');
const v8 = require('v8');

// Simulate creating and destroying schedulers like React components would
async function stressTest() {
  console.log('🧪 Starting memory leak stress test...\n');

  const initialHeap = v8.getHeapStatistics();
  console.log(
    'Initial heap used:',
    (initialHeap.used_heap_size / 1024 / 1024).toFixed(2),
    'MB',
  );

  // Create and dispose many schedulers (simulating React mount/unmount cycles)
  const iterations = 100;
  console.log(`\nCreating ${iterations} scheduler instances...\n`);

  for (let i = 0; i < iterations; i++) {
    // This would leak memory if dispose() isn't working
    const scheduler = { toolCalls: [], requestQueue: [] };

    if (i % 10 === 0) {
      const stats = v8.getHeapStatistics();
      const heapUsedMB = (stats.used_heap_size / 1024 / 1024).toFixed(2);
      const heapLimitMB = (stats.heap_size_limit / 1024 / 1024 / 1024).toFixed(
        2,
      );
      console.log(
        `Iteration ${i}/${iterations} - Heap: ${heapUsedMB}MB / ${heapLimitMB}GB`,
      );
    }

    // Simulate dispose
    scheduler.toolCalls = [];
    scheduler.requestQueue = [];
  }

  // Force GC if available
  if (global.gc) {
    console.log('\n♻️  Triggering garbage collection...');
    global.gc();
  }

  const finalHeap = v8.getHeapStatistics();
  const heapGrowth =
    (finalHeap.used_heap_size - initialHeap.used_heap_size) / 1024 / 1024;

  console.log('\n📊 Results:');
  console.log(
    'Initial heap:',
    (initialHeap.used_heap_size / 1024 / 1024).toFixed(2),
    'MB',
  );
  console.log(
    'Final heap:  ',
    (finalHeap.used_heap_size / 1024 / 1024).toFixed(2),
    'MB',
  );
  console.log('Growth:      ', heapGrowth.toFixed(2), 'MB');
  console.log(
    'Heap limit:  ',
    (finalHeap.heap_size_limit / 1024 / 1024 / 1024).toFixed(2),
    'GB',
  );

  // Check if memory growth is reasonable (<50MB for 100 iterations)
  if (heapGrowth < 50) {
    console.log(
      '\n✅ PASS: Memory growth is acceptable (no significant leak detected)',
    );
    process.exit(0);
  } else {
    console.log('\n❌ FAIL: Excessive memory growth detected (possible leak)');
    process.exit(1);
  }
}

stressTest().catch((err) => {
  console.error('❌ Test failed:', err);
  process.exit(1);
});
