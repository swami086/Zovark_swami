import { useState, useCallback } from 'react';
import { C2_BEACON_STEPS } from '../demo/c2BeaconScenario';
import type { WorkflowStep } from '../types';

export function useDemo() {
  const [steps, setSteps] = useState<WorkflowStep[]>([]);
  const [isRunning, setIsRunning] = useState(false);
  const [isComplete, setIsComplete] = useState(false);

  const startDemo = useCallback(() => {
    setSteps([]);
    setIsRunning(true);
    setIsComplete(false);

    // Reveal steps one by one with cumulative timing
    let cumulativeDelay = 0;
    C2_BEACON_STEPS.forEach((step, index) => {
      const delay = cumulativeDelay + 500; // 500ms between each reveal

      // First show as "running"
      setTimeout(() => {
        setSteps(prev => [...prev, { ...step, status: 'running' as const }]);
      }, delay);

      // Then mark as completed after its duration
      const completeDelay = delay + (step.duration_ms || 500);
      setTimeout(() => {
        setSteps(prev => prev.map((s, i) =>
          i === index ? { ...step, status: 'completed' as const } : s
        ));
        if (index === C2_BEACON_STEPS.length - 1) {
          setIsRunning(false);
          setIsComplete(true);
        }
      }, completeDelay);

      cumulativeDelay = completeDelay;
    });
  }, []);

  return { steps, isRunning, isComplete, startDemo };
}
