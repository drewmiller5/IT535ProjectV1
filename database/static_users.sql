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
  `password` VARCHAR(255) NOT NULL,
  `encrypted_password` VARCHAR(255),
  PRIMARY KEY (`userid`)
) ENGINE=InnoDB;


-- -----------------------------------------------------
-- Generated Users (50)
-- -----------------------------------------------------
INSERT INTO users (username, password) VALUES ('olivia_williams', '1(9]84p(Hp5oE12');
INSERT INTO users (username, password) VALUES ('jimmy_williams', '3agl34flowerh3lLo');
INSERT INTO users (username, password) VALUES ('mbrown', 'c0!mPute5rW1nD0w');
INSERT INTO users (username, password) VALUES ('sophie_garcia', '*F*04x');
INSERT INTO users (username, password) VALUES ('mitchmartin73', '*7wiN$DowgLa$$e$');
INSERT INTO users (username, password) VALUES ('jmartin75', '[?=%7(n-vU)fLSAWEj');
INSERT INTO users (username, password) VALUES ('mikegarcia68', '0d0!or^');
INSERT INTO users (username, password) VALUES ('kgarcia', 'g4iRaFf33wall3*T');
INSERT INTO users (username, password) VALUES ('sgarcia', 'P7n#K*>L_$>(');
INSERT INTO users (username, password) VALUES ('alexander_johnson', 'cHoc0l@*t1e0C3an*b@nan@');
INSERT INTO users (username, password) VALUES ('agarcia', '71g3rGl@$$eSr1$vEr&');
INSERT INTO users (username, password) VALUES ('james.lee', '85*tTywD0BV*C0Fv=');
INSERT INTO users (username, password) VALUES ('kwilliams', '@c^-2dN]gAs7');
INSERT INTO users (username, password) VALUES ('livia.smith', 'lDoYsHyizU3+o5aK<');
INSERT INTO users (username, password) VALUES ('sbrown', '?dt#qWHR539T%*');
INSERT INTO users (username, password) VALUES ('kate_brown', 'aGDXf@oD0mm86[4');
INSERT INTO users (username, password) VALUES ('alexanderbrennan', 'W1ndOW@1H8a7');
INSERT INTO users (username, password) VALUES ('alexmartin70', '^$h7iRt');
INSERT INTO users (username, password) VALUES ('lsmith', ']f_)T*4X5Fd#7S>');
INSERT INTO users (username, password) VALUES ('livia_martin', 'W1nd0W0');
INSERT INTO users (username, password) VALUES ('llee34', 'bicYc2lEW0l1f$UNsH1ne');
INSERT INTO users (username, password) VALUES ('sophiasmith20', '1xDZ!XJfwx7#82');
INSERT INTO users (username, password) VALUES ('kmartin', 'qwerty');
INSERT INTO users (username, password) VALUES ('mikey_williams', '8rNglGaAE<6WQka');
INSERT INTO users (username, password) VALUES ('mbrennan1', 'K4l(A+_F7=[Eg');
INSERT INTO users (username, password) VALUES ('alex_lee', '#wind50wdO9oR');
INSERT INTO users (username, password) VALUES ('sophlee', 'o#C3@N');
INSERT INTO users (username, password) VALUES ('mickey_johnson', 'c0mp9U7%6Erd00r');
INSERT INTO users (username, password) VALUES ('michaelmartin25', 'c@7791');
INSERT INTO users (username, password) VALUES ('jlee', 'i]CA^Z+]Fqh7n7WP<');
INSERT INTO users (username, password) VALUES ('sophia.garcia', 'pantSgir@Ff*3');
INSERT INTO users (username, password) VALUES ('mikey_brown', 'm31rr%Or');
INSERT INTO users (username, password) VALUES ('sophiejohnson', 'BC*w?D2RlMc=Lr-');
INSERT INTO users (username, password) VALUES ('sophia.smith', 'eAgl35b@n@n@pizZ@');
INSERT INTO users (username, password) VALUES ('alexandersmith', 'pic5SBFjr*>F%U');
INSERT INTO users (username, password) VALUES ('katelynnbrennan93', 'be@rMU@siC$GlAs$e$');
INSERT INTO users (username, password) VALUES ('xander.lee', 'FJRAdXrXEtjT0QKk');
INSERT INTO users (username, password) VALUES ('amartin', 'aj&93c}0o%+p');
INSERT INTO users (username, password) VALUES ('mikey_brown1', 'password');
INSERT INTO users (username, password) VALUES ('mickey_garcia', '$aZw]W&2u(e-hf$g');
INSERT INTO users (username, password) VALUES ('katie.garcia', 'W@72cHS#hiR7');
INSERT INTO users (username, password) VALUES ('livgarcia', 'abc123');
INSERT INTO users (username, password) VALUES ('kate.smith', 'U#[)@6*6)W{$Ul^T%4');
INSERT INTO users (username, password) VALUES ('katty_smith', 'bEAR3');
INSERT INTO users (username, password) VALUES ('xander_brennan', 'abc123');
INSERT INTO users (username, password) VALUES ('omartin14', 'm1*Rr0rDoorclOck');
INSERT INTO users (username, password) VALUES ('kattysmith85', 'pENc21lB4aCkpack');
INSERT INTO users (username, password) VALUES ('livwilliams83', 'phonee1@Gl3');
INSERT INTO users (username, password) VALUES ('mlee59', 'b&3a9r');
INSERT INTO users (username, password) VALUES ('jimmy.brown', '{asH1#x>eXbjU-b[0');
 
-- -----------------------------------------------------
-- Base Users (50)
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