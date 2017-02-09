From debian:latest
Run apt-get update && apt-get -y upgrade && apt-get -y install git postgresql sudo
RUN git clone https://gitlab.labs.nic.cz/turris/ucollect
COPY initdb testdb dbconfig /
RUN chmod a+r initdb testdb dbconfig
RUN echo 'local    all             all             trust' >/etc/postgresql/9.4/main/pg_hba.conf
RUN echo 'host    all             all           0.0.0.0/0  trust' >>/etc/postgresql/9.4/main/pg_hba.conf
Run /etc/init.d/postgresql start && sudo -u postgres psql -f testdb && ./initdb debug
