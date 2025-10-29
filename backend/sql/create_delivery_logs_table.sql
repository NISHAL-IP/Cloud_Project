CREATE TABLE dbo.DeliveryLogs (
  LogID INT IDENTITY(1,1) PRIMARY KEY,
  AlertId NVARCHAR(64) NOT NULL,
  Channel NVARCHAR(32) NOT NULL, -- PUSH | EMAIL | SMS
  Recipient NVARCHAR(255) NOT NULL, -- email, phone, or device token
  Status NVARCHAR(32) NOT NULL, -- delivered | failed
  Detail NVARCHAR(4000) NULL,
  CreatedAt DATETIME DEFAULT GETDATE()
);

CREATE INDEX IX_DeliveryLogs_AlertId ON dbo.DeliveryLogs (AlertId);
CREATE INDEX IX_DeliveryLogs_CreatedAt ON dbo.DeliveryLogs (CreatedAt DESC);


