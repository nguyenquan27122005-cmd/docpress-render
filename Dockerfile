FROM mcr.microsoft.com/playwright:v1.64.1-noble

ENV NODE_ENV=production \
    PORT=10000 \
    PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1

WORKDIR /home/pwuser/app

COPY --chown=pwuser:pwuser package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY --chown=pwuser:pwuser studocu.mjs server.mjs probe.mjs THIRD_PARTY_NOTICES.md ./

USER pwuser

EXPOSE 10000

CMD ["node", "server.mjs"]
