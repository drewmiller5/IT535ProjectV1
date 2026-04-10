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


INSERT INTO users (username, password) VALUES ('ojohnson', '7ReUXB=JEcFU');
INSERT INTO users (username, password) VALUES ('billlee66', 'P*H0n!3');
INSERT INTO users (username, password) VALUES ('sophielee1', 'letmein');
INSERT INTO users (username, password) VALUES ('sophlee', 'qwerty');
INSERT INTO users (username, password) VALUES ('katelynnlee', '$Um3mer!');
INSERT INTO users (username, password) VALUES ('swilliams', 'L30p@rDc@Ndl3foot^b@Ll');
INSERT INTO users (username, password) VALUES ('slee59', 'd0gw61n^73R');
INSERT INTO users (username, password) VALUES ('mike_smith', '5D0or');
INSERT INTO users (username, password) VALUES ('sophielee2', 'fR1731nDg1rAFf3le0p@R%d');
INSERT INTO users (username, password) VALUES ('kate.brennan', 'cO]RH6m+HkYjI');
INSERT INTO users (username, password) VALUES ('msmith41', 'HfJczch0bJQ>2L&or>');
INSERT INTO users (username, password) VALUES ('sophiebrown78', 'z0#0+Z1dOHfn');
INSERT INTO users (username, password) VALUES ('sophia.williams1', 'CoM@Pu7erL3oP@RdlI0n');
INSERT INTO users (username, password) VALUES ('jim.johnson', 'CL@0ck@M1rroRl@mp');
INSERT INTO users (username, password) VALUES ('jgarcia', 'welcome');
INSERT INTO users (username, password) VALUES ('sophia.brown1', 'trE3c^aRfRiend2');
INSERT INTO users (username, password) VALUES ('xmartin93', 'D0Lp1H1nM!1Rr0r7Abl3');
INSERT INTO users (username, password) VALUES ('sjohnson54', '$%7@EaK');
INSERT INTO users (username, password) VALUES ('jimmybrown67', 'SKyF0Xh35lLO*');
INSERT INTO users (username, password) VALUES ('mitchgarcia19', '}x&S_9+vH]Q*=+$(');
INSERT INTO users (username, password) VALUES ('liviasmith1', 'welcome');
INSERT INTO users (username, password) VALUES ('sjohnson', '1mm[dhrob4@]T0]l');
INSERT INTO users (username, password) VALUES ('llee85', 'ph*0NEch@1rw2aLl37');
INSERT INTO users (username, password) VALUES ('sbrennan32', 'sOcC3r@@ppL3c@t');
INSERT INTO users (username, password) VALUES ('williamjohnson72', 'S0t3ak');
INSERT INTO users (username, password) VALUES ('liviasmith2', 'welcome');
INSERT INTO users (username, password) VALUES ('sbrown', '3WGHL^xKkr]6');
INSERT INTO users (username, password) VALUES ('mikey.martin', 'l1O&n#');
INSERT INTO users (username, password) VALUES ('bgarcia', 'd0gappl3@flOwer');
INSERT INTO users (username, password) VALUES ('james.brown', '6<1CMj!STOrDeAkji');
INSERT INTO users (username, password) VALUES ('liv.brennan', 'D0Gph0n377');
INSERT INTO users (username, password) VALUES ('sophgarcia70', 'M3irroRChOcOl@7&e');
INSERT INTO users (username, password) VALUES ('abrown17', 'RIVeRphON3b1cyC%l3');
INSERT INTO users (username, password) VALUES ('sbrennan81', 'c0ff38%3D0lPHiN');
INSERT INTO users (username, password) VALUES ('soph_brennan', ')1Phr(oQrMC?EtEh');
INSERT INTO users (username, password) VALUES ('katelynn.lee', 'sum7mer6');
INSERT INTO users (username, password) VALUES ('alexandermartin', 'IjQ[mDRB?<a[vjt');
INSERT INTO users (username, password) VALUES ('alexanderjohnson62', 'abc123');
INSERT INTO users (username, password) VALUES ('will_garcia', '*r1v%er6');
INSERT INTO users (username, password) VALUES ('wmartin', 'Wind@oW');
INSERT INTO users (username, password) VALUES ('livia_brown', '!*w@7ch0CEaNCOmpu7@3R');
INSERT INTO users (username, password) VALUES ('alexsmith17', 'r@bbi47');
INSERT INTO users (username, password) VALUES ('livia.garcia', 'm1rR0rGL@$s30saPpl3');
INSERT INTO users (username, password) VALUES ('jlee', '#fooTbAlLc@rtIGEr');
INSERT INTO users (username, password) VALUES ('livlee67', 'b1Cycleh03LL0');
INSERT INTO users (username, password) VALUES ('sophbrown63', 'le0PArDtR3^E');
INSERT INTO users (username, password) VALUES ('jimwilliams', '$7137@k');
INSERT INTO users (username, password) VALUES ('alexbrown', 'Riv*3*rfO07BaLl');
INSERT INTO users (username, password) VALUES ('abrennan58', '$h6O3$clocK');
INSERT INTO users (username, password) VALUES ('xanderlee', '7igErPH#ONecanDl3');
