#!/bin/bash
mysql -uroot -pPassword1 <<'EOF'
DROP DATABASE IF EXISTS `anime_db`;
CREATE DATABASE `anime_db`;
USE `anime_db`;
DROP TABLE IF EXISTS `anime`;
CREATE TABLE `anime` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(50) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
INSERT INTO `anime` (`name`) VALUES ('Cowboy Bebop');
INSERT INTO `anime` (`name`) VALUES ('Great Teacher Onizuka');
INSERT INTO `anime` (`name`) VALUES ('One Piece');
INSERT INTO `anime` (`name`) VALUES ('Hajime No Ippo');
EOF
