BEGIN TRANSACTION;
CREATE TABLE IF NOT EXISTS "admins" (
	"adminid"	int(11) NOT NULL,
	"adminname"	varchar(255) NOT NULL,
	"adminemail"	varchar(255) NOT NULL,
	"adminpassword"	varchar(255) NOT NULL,
	"adminprofile_photo"	varchar(255) DEFAULT NULL,
	"security_key"	varchar(255) DEFAULT NULL
);
CREATE TABLE IF NOT EXISTS "categories" (
	"categoryid"	INTEGER,
	"categoryname"	VARCHAR(255) NOT NULL,
	"categorystatus"	VARCHAR(100),
	"poster"	TEXT DEFAULT NULL,
	"video"	TEXT DEFAULT NULL,
	PRIMARY KEY("categoryid" AUTOINCREMENT)
);
CREATE TABLE IF NOT EXISTS "contact_form" (
	"contactid"	INTEGER,
	"userid"	INTEGER,
	"username"	TEXT NOT NULL,
	"useremail"	TEXT NOT NULL,
	"reason"	TEXT,
	"subject"	TEXT NOT NULL,
	"description"	TEXT NOT NULL,
	PRIMARY KEY("contactid" AUTOINCREMENT)
);
CREATE TABLE IF NOT EXISTS "contact_replies" (
	"replyid"	INTEGER,
	"contactid"	INTEGER NOT NULL,
	"adminid"	INTEGER,
	"reply_message"	TEXT NOT NULL,
	"reply_date"	DATETIME DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY("replyid" AUTOINCREMENT),
	FOREIGN KEY("contactid") REFERENCES "contact_form"("contactid")
);
CREATE TABLE IF NOT EXISTS "package_types" (
	"packagetypeid"	INTEGER NOT NULL,
	"packagetypename"	VARCHAR(255) NOT NULL,
	"price"	DECIMAL(10, 2) DEFAULT NULL,
	"categoryid"	INTEGER DEFAULT NULL,
	"packagesid"	INTEGER,
	"trainerid"	INTEGER,
	PRIMARY KEY("packagetypeid" AUTOINCREMENT)
);
CREATE TABLE IF NOT EXISTS "payments" (
	"paymentid"	INTEGER,
	"bookingid"	INT,
	"userid"	INT,
	"payment_method"	VARCHAR(50),
	"payment_date"	DATETIME DEFAULT CURRENT_TIMESTAMP,
	"payment_amount"	DECIMAL(10, 2),
	"payment_status"	VARCHAR(20) DEFAULT 'pending',
	PRIMARY KEY("paymentid" AUTOINCREMENT),
	FOREIGN KEY("bookingid") REFERENCES "bookings"("bookingid"),
	FOREIGN KEY("userid") REFERENCES "users"("userid")
);
CREATE TABLE IF NOT EXISTS "users" (
	"userid"	INTEGER,
	"username"	VARCHAR(255) NOT NULL,
	"useremail"	VARCHAR(255) NOT NULL UNIQUE,
	"userpassword"	VARCHAR(255) NOT NULL,
	"userprofile_photo"	VARCHAR(255) DEFAULT NULL,
	"security_key"	VARCHAR(255),
	"registration_date"	DATETIME,
	PRIMARY KEY("userid" AUTOINCREMENT)
);
CREATE TABLE IF NOT EXISTS "trainers" (
	"trainerid"	INTEGER,
	"age"	INTEGER NOT NULL,
	"weight"	DECIMAL(5, 2) NOT NULL,
	"height"	DECIMAL(5, 2) NOT NULL,
	"occupation"	VARCHAR(255) NOT NULL,
	"description"	TEXT,
	"photo"	VARCHAR(255),
	"trainername"	VARCHAR(255) NOT NULL,
	"max_capacity"	INTEGER DEFAULT 5,
	PRIMARY KEY("trainerid" AUTOINCREMENT)
);
CREATE TABLE IF NOT EXISTS "packages" (
	"packagesid"	INTEGER,
	"categoryid"	INTEGER,
	"packagename"	VARCHAR(255) NOT NULL,
	"description"	TEXT DEFAULT NULL,
	"price"	DECIMAL(10, 2) DEFAULT NULL,
	"photo"	VARCHAR(255) DEFAULT NULL,
	"trainerid"	INTEGER,
	PRIMARY KEY("packagesid" AUTOINCREMENT)
);
CREATE TABLE IF NOT EXISTS "bookings" (
	"bookingid"	INTEGER,
	"userid"	INT,
	"categoryid"	INT,
	"categoryname"	VARCHAR(255),
	"packagesid"	INT,
	"packagename"	VARCHAR(255),
	"packagetypeid"	INT,
	"packagetypename"	VARCHAR(255),
	"booking_date"	DATETIME DEFAULT CURRENT_TIMESTAMP,
	"total_price"	DECIMAL(10, 2),
	"status"	VARCHAR(50),
	"invoice_path"	VARCHAR(255),
	"username"	VARCHAR(255),
	"payment_method"	VARCHAR(50),
	"payment_date"	DATETIME,
	"payment_amount"	DECIMAL(10, 2),
	"payment_status"	VARCHAR(20) DEFAULT 'pending',
	"trainerid"	INTEGER,
	"timeid"	INT,
	"trainername"	VARCHAR(255),
	"name"	TEXT NOT NULL DEFAULT '',
	"description"	TEXT NOT NULL DEFAULT '',
	PRIMARY KEY("bookingid" AUTOINCREMENT),
	FOREIGN KEY("userid") REFERENCES "users"("userid"),
	FOREIGN KEY("packagesid") REFERENCES "packages"("packagesid"),
	FOREIGN KEY("packagetypeid") REFERENCES "package_types"("packagetypeid"),
	FOREIGN KEY("categoryid") REFERENCES "categories"("categoryid"),
	FOREIGN KEY("timeid") REFERENCES "times"("timeid"),
	FOREIGN KEY("trainerid") REFERENCES "trainers"("trainerid")
);
CREATE TABLE IF NOT EXISTS "time_slots" (
	"timeid"	INTEGER,
	"name"	TEXT NOT NULL,
	"description"	TEXT NOT NULL,
	"trainerid"	INTEGER,
	"max_bookings"	INTEGER DEFAULT 5,
	"is_full"	BOOLEAN DEFAULT FALSE,
	"booked_count"	INTEGER DEFAULT 0,
	PRIMARY KEY("timeid" AUTOINCREMENT),
	FOREIGN KEY("trainerid") REFERENCES "trainers"("trainerid")
);
INSERT INTO "admins" VALUES (1,'admin
','admin@gmail.com','qwe','image.png','111');
INSERT INTO "categories" VALUES (1,'Yoga',' Physical, Mental, and Spiritual Practice','blog-3.jpg',NULL);
INSERT INTO "categories" VALUES (2,'Cardio','Improve heart health, endurance, and overall fitness','class-3.jpg',NULL);
INSERT INTO "categories" VALUES (3,'Zumba','To be fun, engaging, and effective, offering a full-body workout','Cardio.jpg',NULL);
INSERT INTO "categories" VALUES (4,'Weight Gain','To gain weight healthily and effectively','class-4.jpg',NULL);
INSERT INTO "package_types" VALUES (1,'Silver',30,1,1,NULL);
INSERT INTO "package_types" VALUES (2,'Gold',40,1,1,NULL);
INSERT INTO "package_types" VALUES (3,'Diamond',50,1,1,NULL);
INSERT INTO "package_types" VALUES (4,'Silver',30,1,2,NULL);
INSERT INTO "package_types" VALUES (5,'Gold',40,1,2,NULL);
INSERT INTO "package_types" VALUES (6,'Diamond',50,1,2,NULL);
INSERT INTO "package_types" VALUES (7,'Silver',30,1,3,NULL);
INSERT INTO "package_types" VALUES (8,'Gold',40,1,3,NULL);
INSERT INTO "package_types" VALUES (9,'Diamond',50,1,3,NULL);
INSERT INTO "package_types" VALUES (10,'Silver',30,2,4,NULL);
INSERT INTO "package_types" VALUES (11,'Gold',40,2,4,NULL);
INSERT INTO "package_types" VALUES (12,'Diamond',50,2,4,NULL);
INSERT INTO "package_types" VALUES (13,'Silver',30,2,5,NULL);
INSERT INTO "package_types" VALUES (14,'Gold',40,2,5,NULL);
INSERT INTO "package_types" VALUES (15,'Diamond',50,2,5,NULL);
INSERT INTO "package_types" VALUES (16,'Silver',30,2,6,NULL);
INSERT INTO "package_types" VALUES (17,'Gold',40,2,6,NULL);
INSERT INTO "package_types" VALUES (18,'Diamond
',50,2,6,NULL);
INSERT INTO "package_types" VALUES (19,'Silver',30,3,7,NULL);
INSERT INTO "package_types" VALUES (20,'Gold',40,3,7,NULL);
INSERT INTO "package_types" VALUES (21,'Diamond
',50,3,7,NULL);
INSERT INTO "package_types" VALUES (22,'Silver',30,3,8,NULL);
INSERT INTO "package_types" VALUES (23,'Gold',40,3,8,NULL);
INSERT INTO "package_types" VALUES (24,'Diamond
',50,3,8,NULL);
INSERT INTO "package_types" VALUES (25,'Silver',30,3,9,NULL);
INSERT INTO "package_types" VALUES (26,'Gold',40,3,9,NULL);
INSERT INTO "package_types" VALUES (27,'Diamond
',50,3,9,NULL);
INSERT INTO "package_types" VALUES (28,'Silver',30,4,10,NULL);
INSERT INTO "package_types" VALUES (29,'Gold',40,4,10,NULL);
INSERT INTO "package_types" VALUES (30,'Diamond
',50,4,10,NULL);
INSERT INTO "package_types" VALUES (31,'Silver',30,4,11,NULL);
INSERT INTO "package_types" VALUES (32,'Gold',40,4,11,NULL);
INSERT INTO "package_types" VALUES (33,'Diamond
',50,4,11,NULL);
INSERT INTO "package_types" VALUES (34,'Silver',30,4,12,NULL);
INSERT INTO "package_types" VALUES (35,'Gold',40,4,12,NULL);
INSERT INTO "package_types" VALUES (36,'Diamond
',50,4,12,NULL);
INSERT INTO "payments" VALUES (1,1,1,'credit_card','2024-11-16 20:31:10',130,'completed');
INSERT INTO "payments" VALUES (2,2,1,'credit_card','2024-11-16 20:42:11',120,'completed');
INSERT INTO "payments" VALUES (3,3,1,'credit_card','2024-11-16 23:03:30',110,'completed');
INSERT INTO "payments" VALUES (4,4,1,'credit_card','2024-11-16 23:17:24',80,'completed');
INSERT INTO "payments" VALUES (5,5,1,'credit_card','2024-11-17 01:34:33',110,'completed');
INSERT INTO "payments" VALUES (6,10,1,'credit_card','2024-11-17 12:53:49',130,'completed');
INSERT INTO "payments" VALUES (7,11,1,'credit_card','2024-11-17 13:01:28',130,'completed');
INSERT INTO "payments" VALUES (8,12,1,'credit_card','2024-11-17 13:02:17',90,'completed');
INSERT INTO "payments" VALUES (9,13,1,'credit_card','2024-11-17 13:07:50',130,'completed');
INSERT INTO "payments" VALUES (10,14,1,'credit_card','2024-11-17 19:05:47',100,'completed');
INSERT INTO "payments" VALUES (11,15,1,'credit_card','2024-11-17 19:11:14',100,'completed');
INSERT INTO "payments" VALUES (12,16,1,'credit_card','2024-11-18 01:53:00',130,'completed');
INSERT INTO "payments" VALUES (13,17,1,'credit_card','2024-11-18 01:53:24',130,'completed');
INSERT INTO "payments" VALUES (14,18,1,'credit_card','2024-11-18 01:54:02',130,'completed');
INSERT INTO "payments" VALUES (15,19,1,'credit_card','2024-11-18 01:54:14',130,'completed');
INSERT INTO "payments" VALUES (16,20,1,'credit_card','2024-11-18 01:54:27',130,'completed');
INSERT INTO "payments" VALUES (17,21,1,'credit_card','2024-11-18 01:54:40',110,'completed');
INSERT INTO "payments" VALUES (18,22,1,'credit_card','2024-11-18 02:01:30',130,'completed');
INSERT INTO "payments" VALUES (19,23,1,'paypal','2024-11-18 02:15:51',130,'completed');
INSERT INTO "payments" VALUES (20,24,1,'credit_card','2024-11-18 03:56:56',130,'completed');
INSERT INTO "payments" VALUES (21,25,1,'credit_card','2024-11-18 04:16:52',130,'completed');
INSERT INTO "payments" VALUES (22,26,1,'paypal','2024-11-18 05:05:56',110,'completed');
INSERT INTO "payments" VALUES (23,27,1,'credit_card','2024-11-18 06:12:11',120,'completed');
INSERT INTO "payments" VALUES (24,28,1,'credit_card','2024-11-18 08:40:53',110,'completed');
INSERT INTO "users" VALUES (1,'hha','hha@gmail.com','123',NULL,'123',NULL);
INSERT INTO "trainers" VALUES (1,30,90,190,'Gym Trainer','Our gym trainer provides expert guidance and motivation, tailoring workouts to help members safely and effectively reach their fitness goals. With a focus on technique and progress, they ensure every session is impactful and engaging.','team-2.jpg','Aung Win',5);
INSERT INTO "trainers" VALUES (2,23,80,180,'Gym Trainer','Our gym trainer provides expert guidance and motivation, tailoring workouts to help members safely and effectively reach their fitness goals. With a focus on technique and progress, they ensure every session is impactful and engaging.','team-4.jpg','Ba Thein',5);
INSERT INTO "trainers" VALUES (3,27,100,185,'Gym Trainer','Our gym trainer provides expert guidance and motivation, tailoring workouts to help members safely and effectively reach their fitness goals. With a focus on technique and progress, they ensure every session is impactful and engaging.','team-4.jpg','Tin Shwe',5);
INSERT INTO "trainers" VALUES (4,25,70,180,'Gym Trainer','Our gym trainer provides expert guidance and motivation, tailoring workouts to help members safely and effectively reach their fitness goals. With a focus on technique and progress, they ensure every session is impactful and engaging.','team-1.jpg','Tin Soe',5);
INSERT INTO "trainers" VALUES (5,39,60,180,'Gym Trainer','Our gym trainer provides expert guidance and motivation, tailoring workouts to help members safely and effectively reach their fitness goals. With a focus on technique and progress, they ensure every session is impactful and engaging.','team-6.jpg','Thein Aung',5);
INSERT INTO "trainers" VALUES (6,49,60,170,'Gym Trainer','Our gym trainer provides expert guidance and motivation, tailoring workouts to help members safely and effectively reach their fitness goals. With a focus on technique and progress, they ensure every session is impactful and engaging.','team-5.jpg','Maung Win',5);
INSERT INTO "packages" VALUES (1,1,'One-on-One: Shed & Shred Program',' With a personal trainer for customized workout routines, progress tracking, and one-on-one motivation.',80,'gallery-6.jpg',NULL);
INSERT INTO "packages" VALUES (2,1,'Small Group: Lean Team Sessions','Sessions with a trainer, blending cardio and strength in a motivating group environment.',60,'gallery-7.jpg',NULL);
INSERT INTO "packages" VALUES (3,1,'Without Trainer: Self-Slim Plan','With access to all gym facilities, a general workout plan, and video tutorials for guidance.',50,'gallery-1.jpg',NULL);
INSERT INTO "packages" VALUES (4,2,'One-on-One: Shed & Shred Program',' With a personal trainer for customized workout routines, progress tracking, and one-on-one motivation.',80,'gallery-6.jpg',NULL);
INSERT INTO "packages" VALUES (5,2,'Small Group: Lean Team Sessions','Sessions with a trainer, blending cardio and strength in a motivating group environment.',60,'gallery-7.jpg',NULL);
INSERT INTO "packages" VALUES (6,2,'Without Trainer: Self-Slim Plan','With access to all gym facilities, a general workout plan, and video tutorials for guidance.',50,'gallery-1.jpg',NULL);
INSERT INTO "packages" VALUES (7,3,'One-on-One: Shed & Shred Program',' With a personal trainer for customized workout routines, progress tracking, and one-on-one motivation.',80,'gallery-6.jpg',NULL);
INSERT INTO "packages" VALUES (8,3,'Small Group: Lean Team Sessions','Sessions with a trainer, blending cardio and strength in a motivating group environment.',60,'gallery-7.jpg',NULL);
INSERT INTO "packages" VALUES (9,3,'Without Trainer: Self-Slim Plan','With access to all gym facilities, a general workout plan, and video tutorials for guidance.',50,'gallery-1.jpg',NULL);
INSERT INTO "packages" VALUES (10,4,'One-on-One: Shed & Shred Program',' With a personal trainer for customized workout routines, progress tracking, and one-on-one motivation.',80,'gallery-6.jpg',NULL);
INSERT INTO "packages" VALUES (11,4,'Small Group: Lean Team Sessions','Sessions with a trainer, blending cardio and strength in a motivating group environment.',60,'gallery-7.jpg',NULL);
INSERT INTO "packages" VALUES (12,4,'Without Trainer: Self-Slim Plan','With access to all gym facilities, a general workout plan, and video tutorials for guidance.',50,'gallery-1.jpg',NULL);
INSERT INTO "bookings" VALUES (28,1,1,'Yoga',1,'One-on-One: Shed & Shred Program',1,'Silver','2024-11-18 08:40:53',110,'confirmed','static/invoices/invoice_28.html','hha','credit card','2024-11-18 15:10:53.477470',110,'completed',1,5,'Aung Win','Night','06:00-10:00');
INSERT INTO "time_slots" VALUES (1,'Morning Section','06:00-09:00',1,5,'FALSE',5);
INSERT INTO "time_slots" VALUES (2,'Morning2','09:00-12;00',1,5,0,5);
INSERT INTO "time_slots" VALUES (3,'Afternoon','12:00-03:00',1,5,0,0);
INSERT INTO "time_slots" VALUES (4,'Evening','03:00-06:00',1,5,0,0);
INSERT INTO "time_slots" VALUES (5,'Night','06:00-10:00',1,5,0,3);
COMMIT;
