CREATE DATABASE project_manager;
USE project_manager;
CREATE TABLE members (
id INT PRIMARY KEY,
username VARCHAR(30),
first_name VARCHAR(20) NOT NULL,
last_name VARCHAR(20) NOT NULL,
phone INT(10),
email VARCHAR(30) NOT NULL,
password VARCHAR(15) NOT NULL
);
CREATE TABLE activities (
id INT PRIMARY KEY,
member_id INT NOT NULL,
task VARCHAR(255),
start_date DATE,
end_date DATE,
);
INSERT INTO members (username, first_name, last_name, phone, email, password)
VALUES ('anurag123','Anurag','Sen','9876543210','anurag@gmail.com','$2b$10$iMxrKrqvZv2buojpEJhqDu4LYG7EAmWkDv3u/miE2pv83Vg6mRvFm'),
	   ('vansh123','Vansh','Sen','6542585964','vansh@gmail.com','$2b$10$uVz3VaXaPJWXIyrO/fxbUuHbtJvztt7cP3k9X9lNSot8VuMojvyhq');
SELECT * FROM members;
