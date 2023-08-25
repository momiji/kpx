FROM debian

ENV DEBIAN_FRONTEND noninteractive
RUN apt-get -qq update
RUN apt-get -qq install locales krb5-user squid apache2-utils
RUN apt-get -qq install vim netcat-openbsd curl
RUN apt-get -qq clean

CMD /init-script.sh
