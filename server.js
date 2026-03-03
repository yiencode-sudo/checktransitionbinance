import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import axios from "axios";
import crypto from "crypto";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

const PORT = Number(process.env.PORT || 5000);

const BINANCE_PAY_HOST = (
  process.env.BINANCE_PAY_HOST ||
  process.env.BINANCE_PAY_BASE ||
  "https://bpay.binanceapi.com"
).trim();
const BINANCE_PAY_API_KEY = process.env.BINANCE_PAY_API_KEY;
const BINANCE_PAY_SECRET = process.env.BINANCE_PAY_SECRET;
const BINANCE_SAPI_HOST = (process.env.BINANCE_SAPI_HOST || "https://api.binance.com").trim();
const BINANCE_SPOT_API_KEY = (process.env.BINANCE_SPOT_API_KEY || BINANCE_PAY_API_KEY || "").trim();
const BINANCE_SPOT_API_SECRET = (process.env.BINANCE_SPOT_API_SECRET || BINANCE_PAY_SECRET || "").trim();

app.use((err, req, res, next) => {
  if (err?.type === "entity.parse.failed") {
    return res.status(400).json({ error: "Invalid JSON body" });
  }
  return next(err);
});

/**
 * Binance Pay signature:
 * payload = timestamp + "\n" + nonce + "\n" + body + "\n"
 * signature = HMAC-SHA512(payload, secret).toUpperCase()
 */
function makeNonce32() {
  // 16 bytes => 32 hex chars
  return crypto.randomBytes(16).toString("hex");
}

function signBinancePay({ timestamp, nonce, body }) {
  const payload = `${timestamp}\n${nonce}\n${body}\n`;
  return crypto.createHmac("sha512", BINANCE_PAY_SECRET).update(payload).digest("hex").toUpperCase();
}

async function binancePayPost(path, bodyObj) {
  if (!BINANCE_PAY_API_KEY || !BINANCE_PAY_SECRET) {
    throw new Error("Missing BINANCE_PAY_API_KEY or BINANCE_PAY_SECRET in .env");
  }

  // Binance can be picky about JSON string exactness; keep it compact.
  const body = JSON.stringify(bodyObj);

  const timestamp = Date.now().toString();
  const nonce = makeNonce32();
  const signature = signBinancePay({ timestamp, nonce, body });

  const url = `${BINANCE_PAY_HOST}${path}`;

  const res = await axios.post(url, body, {
    headers: {
      "Content-Type": "application/json",
      "BinancePay-Timestamp": timestamp,
      "BinancePay-Nonce": nonce,
      "BinancePay-Certificate-SN": BINANCE_PAY_API_KEY,
      "BinancePay-Signature": signature,
    },
    timeout: 20000,
  });

  return res.data;
}

function signQueryString(queryString, secret) {
  return crypto.createHmac("sha256", secret).update(queryString).digest("hex");
}

async function binanceSapiPayTransactions({ params = {} }) {
  if (!BINANCE_SPOT_API_KEY || !BINANCE_SPOT_API_SECRET) {
    throw new Error("Missing BINANCE_SPOT_API_KEY/BINANCE_SPOT_API_SECRET (or BINANCE_PAY_API_KEY/BINANCE_PAY_SECRET)");
  }

  const url = `${BINANCE_SAPI_HOST}/sapi/v1/pay/transactions`;

  const cleanParams = {};
  Object.keys(params || {}).forEach((k) => {
    const v = params[k];
    if (v !== undefined && v !== null && String(v).trim() !== "") {
      cleanParams[k] = String(v).trim();
    }
  });

  if (!cleanParams.recvWindow) {
    cleanParams.recvWindow = "5000";
  }
  cleanParams.timestamp = Date.now().toString();

  const queryString = new URLSearchParams(cleanParams).toString();
  const signature = signQueryString(queryString, BINANCE_SPOT_API_SECRET);

  // Official SAPI USER_DATA flow: X-MBX-APIKEY + signature query param.
  const res = await axios.get(url, {
    headers: {
      Accept: "application/json",
      "X-MBX-APIKEY": BINANCE_SPOT_API_KEY,
    },
    params: { ...cleanParams, signature },
    timeout: 20000,
  });

  return res.data;
}

/**
 * GET /api/binance/status/:orderId
 * Query by merchantTradeNo
 * Response: { orderId, status, raw }
 */
app.get("/api/binance/status/:orderId", async (req, res) => {
  try {
    const { orderId } = req.params;

    if (!orderId) {
      return res.status(400).json({ error: "orderId is required" });
    }

    const queryBody = { merchantTradeNo: orderId };
    const data = await binancePayPost("/binancepay/openapi/v3/order/query", queryBody);

    // In query response, transaction status is inside data.data.status (PAY_SUCCESS, etc)
    const d = data?.data || {};
    const orderStatus = d?.status || null;

    return res.json({
      orderId,
      status: orderStatus,
      raw: data,
    });
  } catch (err) {
    const status = err?.response?.status || 500;
    const payload = err?.response?.data || null;

    return res.status(status).json({
      error: err?.message || "Query status failed",
      binance: payload,
    });
  }
});

/**
 * GET/POST /api/binance/transactions
 * Checks Binance Pay transactions via personal-account SAPI signed request.
 * Optional query/body params are forwarded to Binance as URL params.
 */
async function handleTransactions(req, res) {
  try {
    const paramsFromBody =
      req.body && typeof req.body === "object" && req.body.params && typeof req.body.params === "object"
        ? req.body.params
        : {};
    const params = { ...req.query, ...paramsFromBody };

    const data = await binanceSapiPayTransactions({ params });

    return res.json({
      source: "sapi/v1/pay/transactions",
      raw: data,
    });
  } catch (err) {
    const status = err?.response?.status || (/Missing BINANCE_SPOT_API_KEY/i.test(err?.message || "") ? 400 : 500);
    const payload = err?.response?.data || null;

    return res.status(status).json({
      error: err?.message || "Query transactions failed",
      binance: payload,
    });
  }
}

/**
 * GET /api/binance/transactions/:orderId/status
 * Check whether a specific personal-account pay orderId exists in recent history.
 * Optional query params: startTime, endTime, limit, recvWindow
 */
app.get("/api/binance/transactions/:orderId/status", async (req, res) => {
  try {
    const orderId = String(req.params.orderId || "").trim();
    if (!orderId) {
      return res.status(400).json({ error: "orderId is required" });
    }

    const params = { ...req.query };
    if (!params.limit) {
      params.limit = "100";
    }

    const raw = await binanceSapiPayTransactions({ params });
    const rows = Array.isArray(raw?.data) ? raw.data : [];
    const match = rows.find((item) => String(item?.orderId || "") === orderId) || null;

    return res.json({
      orderId,
      paid: Boolean(match),
      status: match ? "PAID" : "NOT_FOUND",
      checkedCount: rows.length,
      transaction: match,
      note: match
        ? "Order exists in returned pay history."
        : "Order not found in returned pay history. Try setting startTime/endTime to narrow the period.",
      rawCode: raw?.code || null,
      rawMessage: raw?.message || null,
    });
  } catch (err) {
    const status = err?.response?.status || (/Missing BINANCE_SPOT_API_KEY/i.test(err?.message || "") ? 400 : 500);
    const payload = err?.response?.data || null;

    return res.status(status).json({
      error: err?.message || "Check order status failed",
      binance: payload,
    });
  }
});

app.get("/api/binance/transactions", handleTransactions);
app.post("/api/binance/transactions", handleTransactions);

app.get("/", (req, res) => {
  res.send("Binance QR Service OK");
});

app.listen(PORT, () => {
  console.log(`[OK] Binance QR service running: http://localhost:${PORT}`);
});
