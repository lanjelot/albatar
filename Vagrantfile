# -*- mode: ruby -*-
# vi: set ft=ruby :

$apt = <<SCRIPT
export DEBIAN_FRONTEND=noninteractive 
apt-get update -y
apt-get install -y python3-dev  # pip

debconf-set-selections <<< "mysql-server mysql-server/root_password password Password1"
debconf-set-selections <<< "mysql-server mysql-server/root_password_again password Password1"

apt-get install -y apache2
apt-get install -y mysql-server
apt-get install -y php libapache2-mod-php php-mysql

sed -i -e 's,^#general_log,general_log,' /etc/mysql/mysql.conf.d/mysqld.cnf
service mysql restart

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

rm -rf /var/www/html/demo
mkdir /var/www/html/demo
cat > /var/www/html/demo/sqli.php <<'EOF'
<?php
$db = new mysqli('localhost', 'root', 'Password1', 'anime_db');
if ($db->connect_errno) {
  die('Failed to connect to DB');
}
$sql = 'SELECT * FROM anime';
if (isset($_REQUEST['id'])) {
  $sql .= " WHERE id = ".$_REQUEST['id'];
}
$result = $db->query($sql);
if (!$result) {
  die($db->error);
}
echo '<html><body><h2>Yay animes!</h2><table border="0">'.mysqli_num_rows($result).' rows fetched', PHP_EOL;
while($row = $result->fetch_array())
{
  echo '<tr><td><a href="/?id='.$row['id'].'">'.$row['id'].'</a></td><td>'.$row['name'].'</td></tr>', PHP_EOL;
}
echo '</table></body></html>', PHP_EOL;
$result->close();
$db->close();
?>
EOF

SCRIPT

$albatar = <<SCRIPT
python3 -m venv albatarenv --without-pip
source albatarenv/bin/activate
wget --quiet -O - https://bootstrap.pypa.io/get-pip.py | python3
python3 -m pip install requests
python3 /vagrant/demo.py -b

SCRIPT

Vagrant.configure(2) do |config|
  config.vm.box = "ubuntu/bionic64"
  config.vm.box_check_update = false
 
  # prevent TTY error messages
  config.ssh.shell = "bash -c 'BASH_ENV=/etc/profile exec bash'"

  config.vm.provision "shell",
                      inline: $apt,
                      preserve_order: true,
                      privileged: true 

  config.vm.provision "shell",
                      inline: $albatar,
                      preserve_order: true,
                      privileged: false
end
