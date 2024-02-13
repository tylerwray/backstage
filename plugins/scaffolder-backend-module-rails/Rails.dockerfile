FROM ruby:3.3@sha256:427354fbbbe5702ab71a660045a70d640b3293530c1e694b4144b670a130f242

RUN apt-get update -qq && \
    apt-get install -y nodejs postgresql-client git && \
    rm -rf /var/lib/apt/lists/

RUN gem install rails
