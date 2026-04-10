-- Allow detection_candidates.status = validation_failed (Sigma transpilation / CLI failure)
ALTER TABLE detection_candidates DROP CONSTRAINT IF EXISTS detection_candidates_status_check;
ALTER TABLE detection_candidates ADD CONSTRAINT detection_candidates_status_check CHECK (status IN (
    'candidate', 'generating', 'validating', 'approved', 'deployed', 'rejected', 'retired', 'validation_failed'
));
