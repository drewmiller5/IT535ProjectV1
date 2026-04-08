/* *********************************************
 MySQL Script for user_system database
********************************************** */

SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0;
SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0;
SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION';

-- *********************************************
-- Create the user_system database
-- Drop if it exists
-- *********************************************
DROP DATABASE IF EXISTS `user_system`;

CREATE DATABASE IF NOT EXISTS `user_system`
    DEFAULT CHARACTER SET utf8mb4;

COMMIT;

-- -----------------------------------------------------
-- Use the database
-- -----------------------------------------------------
USE `user_system`;

-- -----------------------------------------------------
-- Table `user_system`.`users`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `users`;

CREATE TABLE IF NOT EXISTS `users` (
  `userid` INT NOT NULL AUTO_INCREMENT,
  `username` VARCHAR(50) UNIQUE NOT NULL,
  `password` VARCHAR(50) NOT NULL,
  PRIMARY KEY (`userid`)
) ENGINE=InnoDB;

-- -----------------------------------------------------
-- Insert sample users
-- -----------------------------------------------------
INSERT INTO users (username, password) VALUES ('sophie.johnson', 'Fl2oWer$h03s*tabl3');
INSERT INTO users (username, password) VALUES ('william_smith', '2$un$h1N3l@mPB3@r');
INSERT INTO users (username, password) VALUES ('katty_brennan', 'rabb1t*');
INSERT INTO users (username, password) VALUES ('msmith96', 'r1V3%rw1n1DoW');
INSERT INTO users (username, password) VALUES ('mickey.smith', 'r%81verF0x');
INSERT INTO users (username, password) VALUES ('alexander.martin', 'b070kp@n7St7r33');
INSERT INTO users (username, password) VALUES ('katelynn_lee', 't8ig3rfloW34rc0f3f3e');
INSERT INTO users (username, password) VALUES ('willsmith', 'b$1cyClED0gf0x');
INSERT INTO users (username, password) VALUES ('james_lee', '}4gkpcLMKG1#1VDT6');
INSERT INTO users (username, password) VALUES ('sophia_smith', 'password');
INSERT INTO users (username, password) VALUES ('kbrennan', 'cLoc0kfRi3Nd$occ3R');
INSERT INTO users (username, password) VALUES ('liv_johnson', 'HOus3guIt@R0D020R');
INSERT INTO users (username, password) VALUES ('james_garcia', 'nr{Z54CV70lAjIt0s[');
INSERT INTO users (username, password) VALUES ('bmartin', 'bI$c$yCLebo0krabbiT');
INSERT INTO users (username, password) VALUES ('katty_williams', 'tr1E3');
INSERT INTO users (username, password) VALUES ('sophia_lee', '4w!@lL37');
INSERT INTO users (username, password) VALUES ('sophia.brown', 'c@7mU$&1cr@bbit');
INSERT INTO users (username, password) VALUES ('soph_johnson', 'dO$^gCO0*kiE');
INSERT INTO users (username, password) VALUES ('jimjohnson87', 'W)>[d@aR&rvM');
INSERT INTO users (username, password) VALUES ('williamlee', 'abc123');
INSERT INTO users (username, password) VALUES ('jameswilliams52', 'Zpk7HP4CsX<}(>?]');
INSERT INTO users (username, password) VALUES ('mikey_garcia', 'frie$nDd7oor$un$h1n3');
INSERT INTO users (username, password) VALUES ('sophie.brown', 'fO*o87b@ll7I4Ger');
INSERT INTO users (username, password) VALUES ('ssmith61', 'DO#0RwoL!F');
INSERT INTO users (username, password) VALUES ('msmith', 'C!80Ok1337abl3');
INSERT INTO users (username, password) VALUES ('jimsmith', 'b@Se9bA$l5l');
INSERT INTO users (username, password) VALUES ('mgarcia', 'n[S$B^fSyk4V');
INSERT INTO users (username, password) VALUES ('bill.martin', '<MtcSou846amG');
INSERT INTO users (username, password) VALUES ('katie_brennan', 'TR3Eg1^r51@FF3f0x');
INSERT INTO users (username, password) VALUES ('michael.martin', 'win73r$B@nAn@w0aTCH');
INSERT INTO users (username, password) VALUES ('mwilliams', 'c090k1e@gLAs$3$');
INSERT INTO users (username, password) VALUES ('sophmartin14', 'D}OzV?gxd76RR');
INSERT INTO users (username, password) VALUES ('sophiebrown', 'L@8mPmIrR4or');
INSERT INTO users (username, password) VALUES ('sophsmith81', 'bearm1RrorC%anDL3&');
INSERT INTO users (username, password) VALUES ('liviabrown', '-]j5&qU5PKfA');
INSERT INTO users (username, password) VALUES ('xanderjohnson', 'fri$eS7@B0LE');
INSERT INTO users (username, password) VALUES ('katelynnmartin', '4choc0laT%3');
INSERT INTO users (username, password) VALUES ('jim_garcia', 'password');
INSERT INTO users (username, password) VALUES ('bill_smith', 'c@7Co!0kI3!$#hiR7');
INSERT INTO users (username, password) VALUES ('william.johnson', 'T>yjn6[mG@SD_1g');
INSERT INTO users (username, password) VALUES ('liv.martin', 'h@tPhoN3FO0x');
INSERT INTO users (username, password) VALUES ('wlee14', 'ph0n3Gu17@r4l^Ion');
INSERT INTO users (username, password) VALUES ('mike.johnson', 'wAt^chk3y');
INSERT INTO users (username, password) VALUES ('livlee', 'w@l1LE6tbanan@MoUn%7@in');
INSERT INTO users (username, password) VALUES ('alexanderjohnson34', '$FKzF&f3}x[_*');
INSERT INTO users (username, password) VALUES ('kmartin63', 'choc0la7E$mirrOr$');
INSERT INTO users (username, password) VALUES ('billy.smith', 'q-tIozoUNn=tb');
INSERT INTO users (username, password) VALUES ('mmartin', 'wAL*1l37ca7FRiE$2');
INSERT INTO users (username, password) VALUES ('oliviagarcia', 'Sh51r%79');
INSERT INTO users (username, password) VALUES ('mitchlee60', 'gu17A@4rke1y');
        

-- -----------------------------------------------------
-- Create a dedicated user_system_user for access
-- -----------------------------------------------------
DROP USER IF EXISTS 'user_system_user'@'%';

CREATE USER IF NOT EXISTS 'user_system_user'@'%';
GRANT ALL PRIVILEGES ON `user_system`.* TO 'user_system_user'@'%';
ALTER USER 'user_system_user'@'%'
    REQUIRE NONE
    WITH MAX_QUERIES_PER_HOUR 0
    MAX_CONNECTIONS_PER_HOUR 0
    MAX_UPDATES_PER_HOUR 0
    MAX_USER_CONNECTIONS 0;

COMMIT;

SET SQL_MODE=@OLD_SQL_MODE;
SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS;
SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS;