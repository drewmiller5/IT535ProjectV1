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
  `password` VARCHAR(255) NOT NULL,
  `encrypted_password` VARCHAR(255),
  `encrypted_nopep` VARCHAR(255),
  PRIMARY KEY (`userid`)
) ENGINE=InnoDB;

-- -----------------------------------------------------
-- Create Users
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