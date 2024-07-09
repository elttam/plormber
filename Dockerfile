FROM python:3.12.4-slim-bullseye

RUN useradd -m plormber
COPY --chown=plormber:plormber . /home/plormber/plormber
ENV PATH="/home/plormber/.local/bin:$PATH"
USER plormber
WORKDIR /home/plormber/plormber
RUN pip3 install .
ENTRYPOINT [ "plormber" ]