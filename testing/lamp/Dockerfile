FROM ubuntu:24.04

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ENV DEBIAN_FRONTEND=noninteractive 

RUN MYSRP=Password1; \
 { echo "mysql-server mysql-server/root_password password $MYSRP"; \
   echo "mysql-server mysql-server/root_password_again password $MYSRP"; \
 } | debconf-set-selections \
 && apt-get update && apt-get install -y mysql-server \
 && sed -i -e "s/bind-address.*/bind-address = 0.0.0.0/" -e 's,^#general_log,general_log,' /etc/mysql/mysql.conf.d/mysqld.cnf \
 && echo secure_file_priv= >> /etc/mysql/mysql.conf.d/mysqld.cnf \
 && Q0="CREATE USER 'root'@'%' identified by '$MYSRL'" \
 && Q1="GRANT ALL ON *.* TO 'root'@'%' WITH GRANT OPTION" \
 && Q2="FLUSH PRIVILEGES;" \
 && SQL="${Q0}; ${Q1}; ${Q2}" \
 && rm -f /etc/apparmor.d/usr.sbin.mysqld \
 && service mysql start \
 && mysql -uroot -p"$MYSRP" -e "$SQL"

RUN apt-get update && apt-get install -y php libapache2-mod-php php-mysql apache2 \
 && echo 'ServerName localhost' >> /etc/apache2/apache2.conf

RUN apt-get update && apt-get install -y iproute2 lsof vim wget curl gnupg2 unzip \
 && echo 'set bg=dark' > /root/.vimrc

RUN curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor -o /usr/share/keyrings/microsoft-prod.gpg
RUN curl -s -o /etc/apt/sources.list.d/msprod.list https://packages.microsoft.com/config/ubuntu/24.04/prod.list 
RUN apt-get update && ACCEPT_EULA=Y apt-get install -y msodbcsql18 mssql-tools18 unixodbc-dev php-pear php8.3-dev \
 && pecl install sqlsrv \
 && echo extension=sqlsrv.so > /etc/php/8.3/apache2/conf.d/20-sqlsrv.ini

WORKDIR /opt/oracle
RUN wget https://download.oracle.com/otn_software/linux/instantclient/instantclient-basiclite-linuxx64.zip \
 && wget https://download.oracle.com/otn_software/linux/instantclient/instantclient-sdk-linuxx64.zip \
 && wget https://download.oracle.com/otn_software/linux/instantclient/instantclient-sqlplus-linuxx64.zip \
 && unzip -o instantclient-basiclite-linuxx64.zip \
 && unzip -o instantclient-sdk-linuxx64.zip \
 && unzip -o instantclient-sqlplus-linuxx64.zip \
 && rm -f instantclient-basiclite-linuxx64.zip \
 && rm -f instantclient-sdk-linuxx64.zip \
 && rm -f instantclient-sqlplus-linuxx64.zip \
 && mv /opt/oracle/instantclient_* /opt/oracle/instantclient \
 && echo /opt/oracle/instantclient > /etc/ld.so.conf.d/oracle-instantclient.conf \
 && ldconfig

RUN echo instantclient,/opt/oracle/instantclient | pecl install oci8-3.4.0 \
 && echo extension=oci8.so > /etc/php/8.3/apache2/conf.d/20-oci8.ini

RUN apt-get update && apt-get install -y postgresql-client php-pgsql

RUN echo -e "echo Starting services\n\
service mysql start\n\
service apache2 start\n\
bash /var/www/html/demo/setup-mysql.sh\n\
#tail -f /var/log/apache2/error.log\n\
tail -f /dev/null\n" > /usr/local/sbin/start-all-services.sh

CMD ["bash", "/usr/local/sbin/start-all-services.sh"]
