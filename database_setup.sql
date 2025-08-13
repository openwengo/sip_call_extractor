-- Database setup script for SIP Capture PostgreSQL backend
-- This script is run automatically by Docker Compose init scripts
-- The database and user are already created via environment variables

-- Note: Database and user are created by Docker environment variables:
-- POSTGRES_DB, POSTGRES_USER, POSTGRES_PASSWORD

-- Grant schema permissions
GRANT ALL ON SCHEMA public TO sipcapture;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO sipcapture;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO sipcapture;

-- The table will be created automatically by the application, but you can create it manually:
-- Note: This is optional - the application creates the table automatically
CREATE TABLE IF NOT EXISTS sip_calls (
    call_id TEXT NOT NULL,
    instance_id TEXT NOT NULL,
    start_timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    end_timestamp TIMESTAMP WITH TIME ZONE,
    pcap_filename TEXT,
    sip_from TEXT,
    sip_to TEXT,
    s3_location TEXT,
    state TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'finished', 'timedout')),
    rtp_statistics JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    PRIMARY KEY (call_id, instance_id)
);

-- Create indexes for performance (instance-scoped and general)
CREATE INDEX IF NOT EXISTS idx_sip_calls_start_timestamp ON sip_calls(start_timestamp);
CREATE INDEX IF NOT EXISTS idx_sip_calls_created_at ON sip_calls(created_at);
CREATE INDEX IF NOT EXISTS idx_sip_calls_state_instance ON sip_calls(state, instance_id);
CREATE INDEX IF NOT EXISTS idx_sip_calls_sip_from ON sip_calls(sip_from);
CREATE INDEX IF NOT EXISTS idx_sip_calls_sip_to ON sip_calls(sip_to);

-- Grant permissions on the table to the sipcapture user
GRANT ALL PRIVILEGES ON TABLE sip_calls TO sipcapture;

-- Example queries you can run to analyze the data:

-- View active calls
-- SELECT call_id, start_timestamp, sip_from, sip_to, state 
-- FROM sip_calls 
-- WHERE state = 'active' 
-- ORDER BY start_timestamp DESC;

-- View call statistics
-- SELECT 
--     COUNT(*) as total_calls,
--     COUNT(CASE WHEN state = 'active' THEN 1 END) as active_calls,
--     COUNT(CASE WHEN state = 'finished' THEN 1 END) as finished_calls,
--     COUNT(CASE WHEN state = 'timedout' THEN 1 END) as timedout_calls
-- FROM sip_calls;

-- View RTP statistics for a specific call
-- SELECT 
--     call_id, 
--     sip_from, 
--     sip_to,
--     jsonb_pretty(rtp_statistics) as rtp_stats
-- FROM sip_calls 
-- WHERE call_id = 'your_call_id_here';

-- Find calls with high packet loss
-- SELECT 
--     call_id,
--     sip_from,
--     sip_to,
--     stats.value->>'lost_packets' as lost_packets,
--     stats.value->>'packet_count' as total_packets
-- FROM sip_calls,
--      jsonb_array_elements(rtp_statistics) as stats
-- WHERE (stats.value->>'lost_packets')::int > 10
-- ORDER BY (stats.value->>'lost_packets')::int DESC;