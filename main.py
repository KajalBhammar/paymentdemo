import os
import json
import hmac
import base64
import hashlib
import logging
import uuid

from datetime import datetime, timezone
from email.utils import format_datetime
from logging.handlers import TimedRotatingFileHandler

import requests

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from dotenv import load_dotenv


# ============================================================
# LOAD ENVIRONMENT
# ============================================================

load_dotenv()

app = FastAPI()

templates = Jinja2Templates(
    directory="templates"
)


MERCHANT_ID = os.getenv(
    "CYBERSOURCE_MERCHANT_ID"
)

API_KEY = os.getenv(
    "CYBERSOURCE_API_KEY"
)

SHARED_SECRET = os.getenv(
    "CYBERSOURCE_SHARED_SECRET"
)

ENV = os.getenv(
    "CYBERSOURCE_ENV",
    "test"
).strip().lower()


if not MERCHANT_ID:
    raise ValueError(
        "CYBERSOURCE_MERCHANT_ID missing from .env"
    )

if not API_KEY:
    raise ValueError(
        "CYBERSOURCE_API_KEY missing from .env"
    )

if not SHARED_SECRET:
    raise ValueError(
        "CYBERSOURCE_SHARED_SECRET missing from .env"
    )


# ============================================================
# CYBERSOURCE ENVIRONMENT
# ============================================================

if ENV == "production":

    HOST = "api.cybersource.com"

else:

    HOST = "apitest.cybersource.com"


RESOURCE = "/up/v1/capture-contexts"

URL = f"https://{HOST}{RESOURCE}"


# ============================================================
# TARGET ORIGIN
# ============================================================

TARGET_ORIGIN = os.getenv(
    "TARGET_ORIGIN",
    "http://localhost:8000"
).rstrip("/")


# ============================================================
# PAYMENT METHODS
# ============================================================

ALLOWED_METHODS = {

    "PANENTRY",

    "CLICKTOPAY",

    "GOOGLEPAY",

    "CHECK"
}


# ============================================================
# LOG DIRECTORY
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

LOG_DIR = os.path.join(
    BASE_DIR,
    "logs"
)

os.makedirs(
    LOG_DIR,
    exist_ok=True
)


# ============================================================
# CREATE LOGGER
# ============================================================

def create_logger(
    name,
    filename,
    level=logging.INFO
):

    logger = logging.getLogger(
        name
    )

    logger.setLevel(
        level
    )

    logger.propagate = False


    if not logger.handlers:

        handler = TimedRotatingFileHandler(

            os.path.join(
                LOG_DIR,
                filename
            ),

            when="midnight",

            interval=1,

            backupCount=30,

            encoding="utf-8"
        )


        formatter = logging.Formatter(
            "%(asctime)s | %(levelname)s | %(message)s"
        )


        handler.setFormatter(
            formatter
        )


        logger.addHandler(
            handler
        )


    return logger


# ============================================================
# LOGGERS
# ============================================================

request_logger = create_logger(

    "payment_requests",

    "requests.log"
)


response_logger = create_logger(

    "payment_responses",

    "responses.log"
)


error_logger = create_logger(

    "payment_errors",

    "errors.log",

    logging.ERROR
)


# ============================================================
# JSON LOG FUNCTION
# ============================================================

def log_json(
    logger,
    data,
    level="info"
):

    message = json.dumps(
        data,
        ensure_ascii=False,
        separators=(",", ":"),
        default=str
    )


    if level == "error":

        logger.error(
            message
        )

    else:

        logger.info(
            message
        )


# ============================================================
# CYBERSOURCE HTTP SIGNATURE
# ============================================================

def create_headers(
    body: str
):

    digest_bytes = hashlib.sha256(
        body.encode("utf-8")
    ).digest()


    digest = (
        "SHA-256="
        + base64.b64encode(
            digest_bytes
        ).decode("utf-8")
    )


    date = format_datetime(

        datetime.now(
            timezone.utc
        ),

        usegmt=True
    )


    signature_string = (

        f"host: {HOST}\n"

        f"v-c-date: {date}\n"

        f"request-target: post {RESOURCE}\n"

        f"digest: {digest}\n"

        f"v-c-merchant-id: {MERCHANT_ID}"
    )


    try:

        secret = base64.b64decode(
            SHARED_SECRET
        )

    except Exception as exc:

        error_logger.exception(
            "Unable to decode Cybersource shared secret."
        )

        raise RuntimeError(
            "Invalid Cybersource Shared Secret"
        ) from exc


    signature_bytes = hmac.new(

        secret,

        signature_string.encode(
            "utf-8"
        ),

        hashlib.sha256

    ).digest()


    signature = base64.b64encode(
        signature_bytes
    ).decode("utf-8")


    signature_header = (

        f'keyid="{API_KEY}",'

        f'algorithm="HmacSHA256",'

        f'headers="host v-c-date '
        f'request-target digest '
        f'v-c-merchant-id",'

        f'signature="{signature}"'
    )


    return {

        "Content-Type":
            "application/json",

        "Accept":
            "application/jwt",

        "Host":
            HOST,

        "v-c-date":
            date,

        "v-c-merchant-id":
            MERCHANT_ID,

        "Digest":
            digest,

        "Signature":
            signature_header
    }


# ============================================================
# HOME PAGE
# ============================================================

@app.get(
    "/",
    response_class=HTMLResponse
)

async def home(
    request: Request
):

    return templates.TemplateResponse(

        "index.html",

        {

            "request":
                request,

            "environment":
                ENV
        }
    )


# ============================================================
# CREATE CAPTURE CONTEXT
# ============================================================

@app.post(
    "/capture-context"
)

async def capture_context(
    request: Request
):

    # ========================================================
    # UNIQUE INTERNAL REQUEST ID
    # ========================================================

    request_id = str(
        uuid.uuid4()
    )


    started_at = datetime.now(
        timezone.utc
    )


    # ========================================================
    # READ FRONTEND REQUEST
    # ========================================================

    try:

        incoming = await request.json()

    except Exception as exc:

        log_json(

            error_logger,

            {

                "request_id":
                    request_id,

                "event":
                    "INVALID_FRONTEND_JSON",

                "timestamp":
                    started_at.isoformat(),

                "error":
                    str(exc)
            },

            "error"
        )


        raise HTTPException(

            status_code=400,

            detail="Invalid JSON request"
        )


    payment_type = incoming.get(
        "paymentType"
    )


    amount = str(
        incoming.get(
            "amount",
            "10.00"
        )
    )


    # ========================================================
    # CLIENT REFERENCE
    # ========================================================

    client_reference = (

        "TEST-"
        + datetime.now().strftime(
            "%Y%m%d%H%M%S"
        )
        + "-"
        + uuid.uuid4().hex[:6].upper()
    )


    # ========================================================
    # VALIDATE PAYMENT METHOD
    # ========================================================

    if payment_type not in ALLOWED_METHODS:

        log_json(

            error_logger,

            {

                "request_id":
                    request_id,

                "client_reference":
                    client_reference,

                "event":
                    "INVALID_PAYMENT_METHOD",

                "payment_type":
                    payment_type,

                "amount":
                    amount,

                "environment":
                    ENV
            },

            "error"
        )


        raise HTTPException(

            status_code=400,

            detail="Invalid payment method"
        )


    # ========================================================
    # VALIDATE AMOUNT
    # ========================================================

    try:

        amount_number = float(
            amount
        )


        if amount_number <= 0:

            raise ValueError(
                "Amount must be greater than zero."
            )


    except Exception:

        log_json(

            error_logger,

            {

                "request_id":
                    request_id,

                "client_reference":
                    client_reference,

                "event":
                    "INVALID_AMOUNT",

                "amount":
                    amount,

                "payment_type":
                    payment_type
            },

            "error"
        )


        raise HTTPException(

            status_code=400,

            detail="Invalid payment amount"
        )


    # ========================================================
    # BUILD PAYLOAD
    # ========================================================

    payload = {

        "targetOrigins": [

            TARGET_ORIGIN
        ],


        "clientVersion":
            "0.31",


        "country":
            "US",


        "locale":
            "en_US",


        "allowedPaymentTypes": [

            payment_type
        ],


        "allowedCardNetworks": [

            "VISA",

            "MASTERCARD",

            "AMEX"
        ],


        "captureMandate": {

            "billingType":
                "FULL",

            "requestEmail":
                True,

            "requestPhone":
                True,

            "requestShipping":
                False,

            "showAcceptedNetworkIcons":
                True
        },


        "completeMandate": {

            "type":
                "CAPTURE",

            "decisionManager":
                False,

            "consumerAuthentication":
                False
        },


        "data": {

            "orderInformation": {

                "amountDetails": {

                    "totalAmount":
                        amount,

                    "currency":
                        "USD"
                }
            },


            "clientReferenceInformation": {

                "code":
                    client_reference
            }
        }
    }


    # ========================================================
    # REQUEST LOG
    #
    # Deliberately logs only non-sensitive information.
    #
    # DO NOT LOG:
    #
    # API key
    # Shared secret
    # Signature
    # PAN
    # CVV
    # Bank account
    # Capture Context JWT
    # Transient token
    # ========================================================

    log_json(

        request_logger,

        {

            "request_id":
                request_id,

            "client_reference":
                client_reference,

            "event":
                "CAPTURE_CONTEXT_REQUEST",

            "timestamp":
                started_at.isoformat(),

            "environment":
                ENV,

            "cybersource_host":
                HOST,

            "payment_type":
                payment_type,

            "amount":
                amount,

            "currency":
                "USD",

            "country":
                "US",

            "locale":
                "en_US",

            "target_origin":
                TARGET_ORIGIN
        }
    )


    # ========================================================
    # SERIALIZE REQUEST
    # ========================================================

    body = json.dumps(

        payload,

        separators=(
            ",",
            ":"
        )
    )


    # ========================================================
    # AUTHENTICATION HEADERS
    # ========================================================

    try:

        headers = create_headers(
            body
        )

    except Exception as exc:

        log_json(

            error_logger,

            {

                "request_id":
                    request_id,

                "client_reference":
                    client_reference,

                "event":
                    "SIGNATURE_ERROR",

                "timestamp":
                    datetime.now(
                        timezone.utc
                    ).isoformat(),

                "error":
                    str(exc)
            },

            "error"
        )


        raise HTTPException(

            status_code=500,

            detail=(
                "Unable to create "
                "Cybersource authentication."
            )
        )


    # ========================================================
    # CALL CYBERSOURCE
    # ========================================================

    try:

        response = requests.post(

            URL,

            headers=headers,

            data=body,

            timeout=30
        )


    except requests.RequestException as exc:

        finished_at = datetime.now(
            timezone.utc
        )


        duration_ms = int(

            (
                finished_at
                - started_at
            ).total_seconds()
            * 1000
        )


        log_json(

            error_logger,

            {

                "request_id":
                    request_id,

                "client_reference":
                    client_reference,

                "event":
                    "CYBERSOURCE_CONNECTION_ERROR",

                "timestamp":
                    finished_at.isoformat(),

                "payment_type":
                    payment_type,

                "amount":
                    amount,

                "currency":
                    "USD",

                "duration_ms":
                    duration_ms,

                "error":
                    str(exc)
            },

            "error"
        )


        raise HTTPException(

            status_code=502,

            detail=(
                "Unable to connect "
                "to Cybersource."
            )
        )


    # ========================================================
    # RESPONSE TIME
    # ========================================================

    finished_at = datetime.now(
        timezone.utc
    )


    duration_ms = int(

        (
            finished_at
            - started_at
        ).total_seconds()
        * 1000
    )


    # ========================================================
    # CYBERSOURCE ERROR RESPONSE
    # ========================================================

    if response.status_code not in (
        200,
        201
    ):

        # ----------------------------------------------------
        # Error responses normally contain JSON rather than
        # payment credentials. Still avoid logging headers.
        # ----------------------------------------------------

        try:

            cybersource_error = (
                response.json()
            )

        except Exception:

            cybersource_error = {

                "message":
                    response.text[:2000]
            }


        log_json(

            error_logger,

            {

                "request_id":
                    request_id,

                "client_reference":
                    client_reference,

                "event":
                    "CYBERSOURCE_API_ERROR",

                "timestamp":
                    finished_at.isoformat(),

                "environment":
                    ENV,

                "payment_type":
                    payment_type,

                "amount":
                    amount,

                "currency":
                    "USD",

                "http_status":
                    response.status_code,

                "duration_ms":
                    duration_ms,

                "cybersource_error":
                    cybersource_error
            },

            "error"
        )


        raise HTTPException(

            status_code=
                response.status_code,

            detail=
                response.text
        )


    # ========================================================
    # CAPTURE CONTEXT
    # ========================================================

    capture_context_token = (

        response.text
        .strip()
        .strip('"')
    )


    # ========================================================
    # SUCCESS RESPONSE LOG
    #
    # DO NOT STORE THE JWT ITSELF.
    # ========================================================

    log_json(

        response_logger,

        {

            "request_id":
                request_id,

            "client_reference":
                client_reference,

            "event":
                "CAPTURE_CONTEXT_CREATED",

            "timestamp":
                finished_at.isoformat(),

            "environment":
                ENV,

            "payment_type":
                payment_type,

            "amount":
                amount,

            "currency":
                "USD",

            "http_status":
                response.status_code,

            "duration_ms":
                duration_ms,

            "capture_context_created":
                True
        }
    )


    print(
        f"[{request_id}] "
        f"Capture Context created successfully."
    )


    # ========================================================
    # RETURN TO FRONTEND
    # ========================================================

    return {

        "success":
            True,

        "requestId":
            request_id,

        "clientReference":
            client_reference,

        "captureContext":
            capture_context_token
    }


# ============================================================
# FRONTEND TRANSACTION RESULT LOG
#
# complete() happens in the browser.
# After decoding the complete response, index.html can send
# NON-SENSITIVE transaction result fields here.
# ============================================================

@app.post(
    "/payment-log"
)

async def payment_log(
    request: Request
):

    try:

        incoming = await request.json()

    except Exception:

        raise HTTPException(

            status_code=400,

            detail="Invalid log request"
        )


    request_id = incoming.get(
        "requestId",
        "unknown"
    )


    client_reference = incoming.get(
        "clientReference",
        "-"
    )


    status = incoming.get(
        "status",
        "UNKNOWN"
    )


    outcome = incoming.get(
        "outcome",
        "UNKNOWN"
    )


    message = incoming.get(
        "message",
        ""
    )


    transaction_id = incoming.get(
        "transactionId",
        "-"
    )


    approval_code = incoming.get(
        "approvalCode",
        "-"
    )


    response_code = incoming.get(
        "responseCode",
        "-"
    )


    response_details = incoming.get(
        "responseDetails",
        "-"
    )


    amount = incoming.get(
        "amount",
        "-"
    )


    currency = incoming.get(
        "currency",
        "-"
    )


    payment_type = incoming.get(
        "paymentType",
        "-"
    )


    # ========================================================
    # SUCCESS / AUTHORIZED
    # ========================================================

    successful_statuses = {

        "AUTHORIZED",

        "SUCCEEDED",

        "COMPLETED"
    }


    successful = (

        status in successful_statuses

        or

        outcome in successful_statuses
    )


    log_data = {

        "request_id":
            request_id,

        "client_reference":
            client_reference,

        "event":
            (
                "TRANSACTION_SUCCESS"
                if successful
                else
                "TRANSACTION_UNSUCCESSFUL"
            ),

        "timestamp":
            datetime.now(
                timezone.utc
            ).isoformat(),

        "environment":
            ENV,

        "payment_type":
            payment_type,

        "amount":
            amount,

        "currency":
            currency,

        "status":
            status,

        "outcome":
            outcome,

        "message":
            message,

        "transaction_id":
            transaction_id,

        "approval_code":
            approval_code,

        "processor_response_code":
            response_code,

        "response_details":
            response_details
    }


    if successful:

        log_json(

            response_logger,

            log_data
        )

    else:

        log_json(

            error_logger,

            log_data,

            "error"
        )


    return {

        "logged":
            True
    }


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":

    import uvicorn


    uvicorn.run(

        "main:app",

        host="127.0.0.1",

        port=8000,

        reload=True
    )
