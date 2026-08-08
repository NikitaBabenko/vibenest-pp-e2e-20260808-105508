import express from "express";

export function createApp() {
  const app = express();

  app.get("/", (_request, response) => {
    response.type("html").send(`<!doctype html>
      <html lang="en">
        <head><meta charset="utf-8"><title>Project Payments QA</title></head>
        <body><main><h1>Project Payments QA</h1><p>Baseline application.</p></main></body>
      </html>`);
  });

  app.get("/api/me", requireQaBuyer, (request, response) => {
    response.json({ buyerId: request.buyerId });
  });

  return app;
}

function requireQaBuyer(request, response, next) {
  const buyerId = request.get("X-QA-User-Id");
  if (!buyerId) return response.sendStatus(401);
  request.buyerId = buyerId;
  next();
}

if (process.argv[1] && new URL(import.meta.url).pathname.endsWith(process.argv[1].replaceAll("\\", "/"))) {
  createApp().listen(Number.parseInt(process.env.PORT ?? "3000", 10));
}
