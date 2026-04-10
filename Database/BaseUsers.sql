CREATE DATABASE IF NOT EXISTS `user_system`
    DEFAULT CHARACTER SET utf8mb4;

COMMIT;

-- -----------------------------------------------------
-- Use the database
-- -----------------------------------------------------
USE `user_system`;

CREATE TABLE IF NOT EXISTS `users` (
  `userid` INT NOT NULL AUTO_INCREMENT,
  `username` VARCHAR(50) UNIQUE NOT NULL,
  `password` VARCHAR(50) NOT NULL,
  PRIMARY KEY (`userid`)
) ENGINE=InnoDB;

INSERT INTO users (username, password) VALUES
('sophie.johnson', 'Fl2oWer$h03s*tabl3'),
('william_smith', '2$un$h1N3l@mPB3@r'),
('katty_brennan', 'rabb1t*'),
('msmith96', 'r1V3%rw1n1DoW'),
('mickey.smith', 'r%81verF0x'),
('alexander.martin', 'b070kp@n7St7r33'),
('katelynn_lee', 't8ig3rfloW34rc0f3f3e'),
('willsmith', 'b$1cyClED0gf0x'),
('james_lee', '}4gkpcLMKG1#1VDT6'),
('sophia_smith', 'password'),
('kbrennan', 'cLoc0kfRi3Nd$occ3R'),
('liv_johnson', 'HOus3guIt@R0D020R'),
('james_garcia', 'nr{Z54CV70lAjIt0s['),
('bmartin', 'bI$c$yCLebo0krabbiT'),
('katty_williams', 'tr1E3'),
('sophia_lee', '4w!@lL37'),
('sophia.brown', 'c@7mU$&1cr@bbit'),
('soph_johnson', 'dO$^gCO0*kiE'),
('jimjohnson87', 'W)>[d@aR&rvM'),
('williamlee', 'abc123'),
('jameswilliams52', 'Zpk7HP4CsX<}(>?]'),
('mikey_garcia', 'frie$nDd7oor$un$h1n3'),
('sophie.brown', 'fO*o87b@ll7I4Ger'),
('ssmith61', 'DO#0RwoL!F'),
('msmith', 'C!80Ok1337abl3'),
('jimsmith', 'b@Se9bA$l5l'),
('mgarcia', 'n[S$B^fSyk4V'),
('bill.martin', '<MtcSou846amG'),
('katie_brennan', 'TR3Eg1^r51@FF3f0x'),
('michael.martin', 'win73r$B@nAn@w0aTCH'),
('mwilliams', 'c090k1e@gLAs$3$'),
('sophmartin14', 'D}OzV?gxd76RR'),
('sophiebrown', 'L@8mPmIrR4or'),
('sophsmith81', 'bearm1RrorC%anDL3&'),
('liviabrown', '-]j5&qU5PKfA'),
('xanderjohnson', 'fri$eS7@B0LE'),
('katelynnmartin', '4choc0laT%3'),
('jim_garcia', 'password'),
('bill_smith', 'c@7Co!0kI3!$#hiR7'),
('william.johnson', 'T>yjn6[mG@SD_1g'),
('liv.martin', 'h@tPhoN3FO0x'),
('wlee14', 'ph0n3Gu17@r4l^Ion'),
('mike.johnson', 'wAt^chk3y'),
('livlee', 'w@l1LE6tbanan@MoUn%7@in'),
('alexanderjohnson34', '$FKzF&f3}x[_*'),
('kmartin63', 'choc0la7E$mirrOr$'),
('billy.smith', 'q-tIozoUNn=tb'),
('mmartin', 'wAL*1l37ca7FRiE$2'),
('oliviagarcia', 'Sh51r%79'),
('mitchlee60', 'gu17A@4rke1y');