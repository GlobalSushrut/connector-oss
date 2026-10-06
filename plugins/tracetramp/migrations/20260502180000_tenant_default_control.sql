-- Control (enforce + observe) is the default tenant posture; View is opt-in via server config + header.
ALTER TABLE tenants ALTER COLUMN default_mode SET DEFAULT 'control';
UPDATE tenants SET default_mode = 'control' WHERE id = 'default' AND default_mode = 'view';
