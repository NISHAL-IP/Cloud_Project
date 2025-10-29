ALTER TABLE dbo.Users
ADD Role NVARCHAR(20) DEFAULT 'student' NOT NULL;

-- Update existing users to have student role
UPDATE dbo.Users SET Role = 'student' WHERE Role IS NULL;
