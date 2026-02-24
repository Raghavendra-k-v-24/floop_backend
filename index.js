import express from "express";
import path from "path";
import cors from "cors";
import axios from "axios";
import { URL } from "url";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import crypto from "crypto";
import AWS from "aws-sdk";
import * as cheerio from "cheerio";
import mongoose from "mongoose";
import { createHash } from "crypto";
import bodyParser from "body-parser";
import * as screenshotone from "screenshotone-api-sdk";

import { authenticate } from "./middleware/auth.js";

import {
  User,
  Portfolio,
  Review,
  Pin,
  Comment,
  Event,
} from "./database/index.js";
import { logEvent } from "./utils/logEvent.js";

dotenv.config();

const app = express();

const s3 = new AWS.S3();

const screenshotClient = new screenshotone.Client(
  process.env.SCREENSHOTONE_ACCESS_KEY,
  process.env.SCREENSHOTONE_SECRET_KEY,
);

const BASE_URL_CLIENT = process.env.BASE_URL_CLIENT;
const BASE_URL_SERVER = process.env.BASE_URL_SERVER;

app.use(
  cors({
    origin: BASE_URL_CLIENT,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  }),
);
app.use(bodyParser.json());
app.use(express.static(path.join(process.cwd(), "public")));

// helper function
function urlToHashedS3Key(url) {
  const parsed = new URL(url);

  const clean = parsed.host + parsed.pathname.replace(/\/+$/, "");

  return createHash("sha256").update(clean).digest("hex");
}

async function getImage(portfolioLink) {
  const bucket = process.env.AWS_S3_BUCKET_NAME;
  const key = `screenshots/${urlToHashedS3Key(portfolioLink)}.png`;

  try {
    await s3
      .headObject({
        Bucket: bucket,
        Key: key,
      })
      .promise();

    // ✅ Cached
    return {
      key,
      cached: true,
    };
  } catch (err) {
    // ❌ Not found → continue
  }

  const options = screenshotone.TakeOptions.url(portfolioLink)
    .delay(3)
    .blockAds(true);

  // 3️⃣ Take screenshot (ONLY ONCE)
  const imageBlob = await screenshotClient.take(options);
  const buffer = Buffer.from(await imageBlob.arrayBuffer());

  // 4️⃣ Upload to S3
  await s3
    .putObject({
      Bucket: bucket,
      Key: key,
      Body: buffer,
      ContentType: "image/png",
      CacheControl: "public, max-age=31536000",
    })
    .promise();

  // 5️⃣ Return S3 URL
  return {
    key,
    cached: false,
  };
}

function getPresignedImageUrl(key) {
  return s3.getSignedUrl("getObject", {
    Bucket: process.env.AWS_S3_BUCKET_NAME,
    Key: key,
    Expires: 60 * 60 * 24, // 24 hours
  });
}

// apis
app.post("/api/signup", async (req, res) => {
  try {
    const data = req.body;
    const { name, email, password } = data;

    if (!name || !email || !password) {
      return res.status(400).json({ message: "Missing required fields" });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "Email already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      name,
      email,
      password: hashedPassword,
    });
    await user.save();

    await logEvent({
      userId: user._id,
      event: "USER_REGISTERED",
    });

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
      expiresIn: "1d",
    });

    return res
      .status(201)
      .json({ message: "User created successfully", token });
  } catch (err) {
    console.error("Signing up user error:", err);
    return res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const data = req.body;
    const { email, password } = data;

    if (!email || !password) {
      return res
        .status(400)
        .json({ message: "Email and password are required" });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "User not found" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
      expiresIn: "1d",
    });

    return res
      .status(201)
      .json({ message: "User created successfully", token });
  } catch (err) {
    console.error("Logging in user error:", err);
    return res.status(500).json({ message: "Internal server error" });
  }
});

app.put("/api/user", authenticate, async (req, res) => {
  try {
    const data = req.body;
    const { name, password, role } = data;
    const updateQuery = {};
    const setFields = {};
    const addToSetFields = {};

    // normal fields → $set
    if (name) setFields.name = name;

    if (password) {
      setFields.password = await bcrypt.hash(password, 10);
    }

    // array append fields → $addToSet
    if (role) {
      addToSetFields.role = role;
    }

    // attach operators only if needed
    if (Object.keys(setFields).length > 0) {
      updateQuery.$set = setFields;
    }

    if (Object.keys(addToSetFields).length > 0) {
      updateQuery.$addToSet = addToSetFields;
    }

    if (Object.keys(updateQuery).length === 0) {
      return res.status(400).json({ message: "No valid fields to update" });
    }

    await User.findByIdAndUpdate(req.userId, updateQuery, { new: true });

    return res.status(200).json({ message: "User updated successfully" });
  } catch (err) {
    console.error("Update user error:", err);
    return res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/api/portfolio", authenticate, async (req, res) => {
  try {
    const data = req.body;
    const { portfolioLink, intent } = data;

    if (!portfolioLink) {
      return res.status(400).json({ message: "Missing required fields" });
    }

    const ownerUserId = intent === "reviewee" ? req.userId : null;
    const createdByUserId = req.userId;

    const { key, cached } = await getImage(portfolioLink);

    const portfolio = new Portfolio({
      ownerUserId,
      createdByUserId,
      portfolioLink,
      portfolioImage: key,
    });
    await portfolio.save();

    await logEvent({
      userId: req.userId,
      portfolioId: portfolio._id,
      event: "PORTFOLIO_CREATED",
    });

    return res
      .status(201)
      .json({ message: "Portfolio created successfully", portfolio });
  } catch (err) {
    console.error("Portfolio creation error", err);
    return res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/api/review", authenticate, async (req, res) => {
  try {
    const userId = new mongoose.Types.ObjectId(req.userId);
    const { type } = req.query; // received | given

    let match = {};

    if (type === "received") {
      match.revieweeId = userId;
    } else if (type === "given") {
      match.reviewerId = userId;
    } else {
      return res.status(400).json({
        message: "type must be 'received' or 'given'",
      });
    }

    const reviews = await Review.aggregate([
      { $match: match },

      // 🔗 Join portfolio
      {
        $lookup: {
          from: "portfolio",
          localField: "portfolioId",
          foreignField: "_id",
          as: "portfolio",
        },
      },
      { $unwind: "$portfolio" },

      // 👤 Join reviewer user (if exists)
      {
        $lookup: {
          from: "user",
          localField: "reviewerId",
          foreignField: "_id",
          as: "reviewer",
        },
      },
      {
        $unwind: {
          path: "$reviewer",
          preserveNullAndEmptyArrays: true,
        },
      },

      // 💬 Count feedback (comments)
      {
        $lookup: {
          from: "comment",
          let: { reviewId: "$_id" },
          pipeline: [
            {
              $lookup: {
                from: "pin",
                localField: "pinId",
                foreignField: "_id",
                as: "pin",
              },
            },
            { $unwind: "$pin" },
            {
              $match: {
                $expr: { $eq: ["$pin.reviewId", "$$reviewId"] },
              },
            },
            { $count: "count" },
          ],
          as: "feedbackCount",
        },
      },

      // 🧮 Shape response
      {
        $addFields: {
          reviewerDisplayName: {
            $cond: [
              { $ifNull: ["$reviewer.name", false] },
              "$reviewer.name",
              {
                $cond: [
                  { $ifNull: ["$invitedReviewerEmail", false] },
                  {
                    $concat: ["$invitedReviewerEmail", " (invited to floop)"],
                  },
                  "Not assigned",
                ],
              },
            ],
          },
          feedbackCount: {
            $ifNull: [{ $arrayElemAt: ["$feedbackCount.count", 0] }, 0],
          },
          reviewLink: {
            $concat: [
              process.env.BASE_URL_CLIENT,
              "/review/",
              { $toString: "$accessToken" },
            ],
          },
        },
      },

      // 📤 Final projection
      {
        $project: {
          _id: 1,
          status: 1,
          createdAt: 1,

          reviewerDisplayName: 1,
          feedbackCount: 1,
          reviewLink: 1,

          portfolio: {
            portfolioLink: 1,
            isOpened: 1,
            openCount: 1,
            lastOpenedAt: 1,
            portfolioImage: 1,
          },
        },
      },

      { $sort: { createdAt: -1 } },
    ]);

    const reviewsWithSignedImages = reviews.map((review) => {
      const key = review.portfolio?.portfolioImage;

      if (!key) {
        return review;
      }

      return {
        ...review,
        portfolio: {
          ...review.portfolio,
          portfolioImage: getPresignedImageUrl(key),
        },
      };
    });

    return res.status(200).json({ reviews: reviewsWithSignedImages });
  } catch (err) {
    console.error("Get reviews error", err);
    return res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/api/review", authenticate, async (req, res) => {
  try {
    const { portfolioId, reviewerEmail, revieweeEmail, intent } = req.body;

    const userId = req.userId;

    if (!portfolioId) {
      return res.status(400).json({ message: "portfolioId is required" });
    }

    if (!["reviewee", "reviewer"].includes(intent)) {
      return res.status(400).json({ message: "Invalid intent" });
    }

    const user = await User.findById(userId);

    // // 🔐 Validate intent against capability
    // if (!user.role.includes(intent)) {
    //   return res.status(403).json({
    //     message: `User cannot create review as ${intent}`,
    //   });
    // }

    let revieweeId = null;
    let reviewerId = null;
    let invitedReviewerEmail = null;

    if (intent === "reviewee") {
      revieweeId = userId;

      if (reviewerEmail) {
        const reviewer = await User.findOne(
          { email: reviewerEmail },
          { _id: 1 },
        );
        reviewerId = reviewer?._id || null;
        invitedReviewerEmail = reviewerEmail;
      }
    }

    if (intent === "reviewer") {
      reviewerId = userId;

      if (revieweeEmail) {
        const reviewee = await User.findOne(
          { email: revieweeEmail },
          { _id: 1 },
        );
        revieweeId = reviewee?._id || null;
      }
    }

    const accessToken = crypto.randomBytes(24).toString("hex");

    const review = await Review.create({
      portfolioId,
      createdByUserId: userId,
      intent,
      revieweeId,
      reviewerId,
      invitedReviewerEmail,
      accessToken,
    });

    await logEvent({
      userId: req.userId,
      portfolioId,
      reviewId: review._id,
      event: "REVIEW_SHARED",
      metadata: {
        invitedEmail: invitedReviewerEmail,
      },
    });

    return res.status(201).json({
      message: "Review created successfully",
      review,
    });
  } catch (err) {
    console.error("Review creation error", err);
    return res.status(500).json({ message: "Internal server error" });
  }
});

app.put("/api/review", authenticate, async (req, res) => {
  try {
    const data = req.body;
    const { reviewId, goals, accessType } = data;
    const revieweeId = req.userId;

    if (!reviewId) {
      return res.status(400).json({ message: "reviewId is required" });
    }

    const updateQuery = {};
    const setFields = {};
    // const addToSetFields = {};

    // normal fields → $set
    if (accessType) setFields.accessType = accessType;

    if (Array.isArray(goals) && goals.length > 0) {
      setFields.goals = goals;
    }

    // attach operators only if needed
    if (Object.keys(setFields).length > 0) {
      updateQuery.$set = setFields;
    }

    // if (Object.keys(addToSetFields).length > 0) {
    //   updateQuery.$addToSet = addToSetFields;
    // }

    if (Object.keys(updateQuery).length === 0) {
      return res.status(400).json({ message: "No valid fields to update" });
    }

    const updatedReview = await Review.findOneAndUpdate(
      { _id: reviewId, revieweeId }, // only owner can update
      updateQuery,
      { new: true },
    );

    if (!updatedReview) {
      return res
        .status(404)
        .json({ message: "Review not found or unauthorized" });
    }

    return res.status(200).json({ message: "Review updated successfully" });
  } catch (err) {
    console.error("Review update error:", err);
    return res.status(500).json({ message: "Internal server error" });
  }
});

// app.get("/api/proxy", async (req, res) => {
//   const { url, reviewId, token } = req.query;

//   if (!url || !reviewId) {
//     return res.status(400).send("Missing url or reviewId");
//   }

//   try {
//     const response = await axios.get(url, {
//       responseType: "arraybuffer",
//       headers: { "User-Agent": "Mozilla/5.0" },
//       timeout: 15000,
//     });

//     const contentType = response.headers["content-type"] || "";
//     res.setHeader("Content-Type", contentType);

//     // Non-HTML → passthrough
//     if (!contentType.includes("text/html")) {
//       return res.send(response.data);
//     }

//     const html = response.data.toString("utf8");
//     const $ = cheerio.load(html);
//     const baseUrl = new URL(url);

//     // Rewrite only <a> navigation
//     $("a[href]").each((_, el) => {
//       const href = $(el).attr("href");
//       if (!href || href.startsWith("#") || href.startsWith("mailto:")) return;

//       const absolute = href.startsWith("http")
//         ? href
//         : new URL(href, baseUrl).toString();

//       $(el).attr(
//         "href",
//         `/api/proxy?url=${encodeURIComponent(absolute)}&reviewId=${reviewId}`,
//       );
//     });

//     // Inject overlay
//     $("head").append(`
//       <script>
//         window.__FLOOP__ = {
//           reviewId: "${reviewId}",
//           token: "${token || ""}"
//         };
//       </script>
//       <script src="${process.env.BASE_URL_CLIENT}/overlay.js" defer></script>
//     `);

//     res.send($.html());
//   } catch (err) {
//     console.error("Proxy error:", err.message);
//     res.status(500).send("Proxy failed");
//   }
// });

app.get("/api/proxy", async (req, res) => {
  const { url, reviewId } = req.query;

  if (!url || !reviewId) {
    return res.status(400).send("Missing url or reviewId");
  }

  try {
    const response = await axios({
      url,
      method: "GET",
      responseType: "stream",
      timeout: 8000,
      headers: {
        "User-Agent": "Mozilla/5.0",
      },
    });

    const contentType = response.headers["content-type"] || "";

    res.setHeader("Content-Type", contentType);
    res.setHeader("X-Frame-Options", "ALLOWALL");
    res.setHeader("Content-Security-Policy", "frame-ancestors *;");

    // ✅ NON HTML → stream directly
    if (!contentType.includes("text/html")) {
      return response.data.pipe(res);
    }

    // Convert stream → string ONLY for HTML
    let html = "";

    response.data.on("data", (chunk) => {
      html += chunk.toString();
    });

    response.data.on("end", () => {
      const $ = cheerio.load(html);
      const baseUrl = new URL(url);

      // ⭐ MAGIC LINE
      $("head").prepend(`<base href="${baseUrl.origin}">`);

      // Rewrite navigation only
      $("a[href]").each((_, el) => {
        const href = $(el).attr("href");

        if (!href || href.startsWith("#") || href.startsWith("mailto:")) return;

        const absolute = href.startsWith("http")
          ? href
          : new URL(href, baseUrl).toString();

        $(el).attr(
          "href",
          `/api/proxy?url=${encodeURIComponent(absolute)}&reviewId=${reviewId}`,
        );
      });

      // Inject overlay
      $("head").append(`
        <script>
          window.__FLOOP__ = { reviewId: "${reviewId}", apiBase: "${process.env.BASE_URL_SERVER}" };
        </script>
        <script src="${process.env.BASE_URL_CLIENT}/overlay.js" defer></script>
      `);

      res.send($.html());
    });
  } catch (err) {
    console.error("Proxy error:", err.message);
    res.status(500).send("Proxy failed");
  }
});

// generating proxy url for frontend
app.get("/api/review/:id/view", async (req, res) => {
  try {
    const accessToken = req.params.id;
    const userId = req.userId || null;

    const review = await Review.findOne({ accessToken })
      .populate("portfolioId", "portfolioLink")
      .populate("revieweeId", "name email")
      .populate("reviewerId", "name email");

    if (!review) {
      return res.status(404).json({ message: "Review not found" });
    }

    if (review.revieweeId) {
      const FIVE_MIN = 1000 * 60 * 5;

      const existing = await Event.findOne({
        userId: review.revieweeId,
        reviewId: review._id,
        event: "PORTFOLIO_OPENED",
        "metadata.actorId": review.reviewerId || null,
      }).sort({ createdAt: -1 });

      const shouldLog =
        !existing ||
        Date.now() - new Date(existing.createdAt).getTime() > FIVE_MIN;

      if (shouldLog) {
        await logEvent({
          userId: review.revieweeId,
          portfolioId: review.portfolioId,
          reviewId: review._id,
          event: "PORTFOLIO_OPENED",
          metadata: {
            actorId: review.reviewerId || null,
          },
        });
      }
    }

    // // 🔐 Access check
    // const isLoggedInAllowed =
    //   userId &&
    //   (review.revieweeId?.equals(userId) || review.reviewerId?.equals(userId));

    // const isTokenAllowed = !!review.accessToken;

    // if (!isLoggedInAllowed && !isTokenAllowed) {
    //   return res.status(403).json({ message: "Access denied" });
    // }
    const revieweeName = review.revieweeId?.name || "Unknown";
    const reviewerName = review.reviewerId?.name || "Unknown";

    // ✅ Build proxy URL (frontend never does this)
    const proxyUrl =
      `${BASE_URL_SERVER}/api/proxy?url=${encodeURIComponent(review.portfolioId.portfolioLink)}` +
      `&reviewId=${review._id}`;
    return res.json({
      proxyUrl,
      revieweeName,
      reviewerName,
      portfolioLink: review.portfolioId.portfolioLink,
    });
  } catch (err) {
    console.error("Review view error", err);
    return res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/api/pin", async (req, res) => {
  const { reviewId, pageUrl, x, y, selector, comment, textHint, tagName } =
    req.body;

  // if (!(await canAccessReview(reviewId, req.userId, token))) {
  //   return res.status(403).json({ message: "Access denied" });
  // }

  const pin = await Pin.create({
    reviewId,
    pageUrl,
    position: { x, y },
    selector,
    textHint,
    tagName,
    createdBy: req.userId || null,
  });

  await logEvent({
    userId: req.userId || null,
    reviewId,
    event: "PIN_ADDED",
  });

  await Comment.create({
    pinId: pin._id,
    authorId: req.userId || null,
    content: comment,
  });

  const review = await Review.findById(reviewId);

  if (req.userId) {
    await logEvent({
      userId: req.userId,
      portfolioId: review.portfolioId,
      reviewId,
      event: "COMMENT_ADDED",
    });
  }

  if (review.revieweeId) {
    await logEvent({
      userId: review.revieweeId,
      portfolioId: review.portfolioId,
      reviewId,
      event: "COMMENT_RECEIVED",
      metadata: {
        actorId: review.reviewerId || null,
        actorEmail: review.invitedReviewerEmail || null,
      },
    });
  }

  res.status(201).json({ pin });
});

app.get("/api/pin", async (req, res) => {
  try {
    const { reviewId } = req.query;

    const pins = await Pin.find({ reviewId }).lean();

    const pinIds = pins.map((p) => p._id);

    const comments = await Comment.find({
      pinId: { $in: pinIds },
    }).lean();

    // group comments by pinId
    const commentMap = {};
    comments.forEach((c) => {
      commentMap[c.pinId.toString()] = c;
    });

    const result = pins.map((p) => ({
      ...p,
      comment: commentMap[p._id.toString()]?.content || "",
    }));

    res.json(result);
  } catch (err) {
    res.status(500).json({ message: "Failed to load pins" });
  }
});

app.get("/api/dashboard/stats", authenticate, async (req, res) => {
  try {
    const userId = new mongoose.Types.ObjectId(req.userId);

    // Received
    const received = await Review.aggregate([
      { $match: { revieweeId: userId } },
      {
        $lookup: {
          from: "pin",
          localField: "_id",
          foreignField: "reviewId",
          as: "pins",
        },
      },
      { $unwind: { path: "$pins", preserveNullAndEmptyArrays: true } },
      {
        $lookup: {
          from: "comment",
          localField: "pins._id",
          foreignField: "pinId",
          as: "comments",
        },
      },
      {
        $group: {
          _id: null,
          reviews: { $addToSet: "$_id" },
          comments: { $sum: { $size: "$comments" } },
        },
      },
      {
        $project: {
          _id: 0,
          reviewCount: { $size: "$reviews" },
          commentCount: "$comments",
        },
      },
    ]);

    // Given
    const given = await Review.aggregate([
      { $match: { reviewerId: userId } },
      {
        $lookup: {
          from: "pin",
          localField: "_id",
          foreignField: "reviewId",
          as: "pins",
        },
      },
      { $unwind: { path: "$pins", preserveNullAndEmptyArrays: true } },
      {
        $lookup: {
          from: "comment",
          localField: "pins._id",
          foreignField: "pinId",
          as: "comments",
        },
      },
      {
        $group: {
          _id: null,
          reviews: { $addToSet: "$_id" },
          comments: { $sum: { $size: "$comments" } },
        },
      },
      {
        $project: {
          _id: 0,
          reviewCount: { $size: "$reviews" },
          commentCount: "$comments",
        },
      },
    ]);

    res.json({
      received: received[0] || { reviewCount: 0, commentCount: 0 },
      given: given[0] || { reviewCount: 0, commentCount: 0 },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Failed to fetch stats" });
  }
});

app.get("/api/activity", authenticate, async (req, res) => {
  try {
    const userId = new mongoose.Types.ObjectId(req.userId);
    const { type } = req.query; // received | given

    //////////////////////////////////////////////////////
    // ⭐ GROUP SIMILAR EVENTS (5 min window)
    //////////////////////////////////////////////////////

    const match =
      type === "given"
        ? {
            userId,
            event: {
              $in: [
                "REVIEW_SHARED",
                "COMMENT_ADDED",
                "PIN_ADDED",
                "PORTFOLIO_CREATED",
              ],
            },
          }
        : {
            userId,
            event: {
              $in: ["COMMENT_RECEIVED", "PORTFOLIO_OPENED"],
            },
          };

    const events = await Event.aggregate([
      { $match: match },

      {
        $lookup: {
          from: "portfolio",
          localField: "portfolioId",
          foreignField: "_id",
          as: "portfolio",
        },
      },
      { $unwind: { path: "$portfolio", preserveNullAndEmptyArrays: true } },

      {
        $lookup: {
          from: "user",
          localField: "metadata.actorId",
          foreignField: "_id",
          as: "actor",
        },
      },
      { $unwind: { path: "$actor", preserveNullAndEmptyArrays: true } },

      {
        $project: {
          event: 1,
          metadata: 1,
          createdAt: 1,
          portfolioLink: "$portfolio.portfolioLink",
          actorName: "$actor.name",
        },
      },

      // ⭐ HARD DEDUPE
      {
        $group: {
          _id: "$_id",
          doc: { $first: "$$ROOT" },
        },
      },
      { $replaceRoot: { newRoot: "$doc" } },

      { $sort: { createdAt: -1 } },
      { $limit: 50 },
    ]);

    const GROUP_WINDOW = 1000 * 60 * 5;

    const groupedEvents = [];

    events.forEach((event) => {
      // ⭐ find matching group
      const group = groupedEvents.find((g) => {
        const sameEvent = g.event === event.event;
        const sameActor = g.actorName === event.actorName;
        const samePortfolio = g.portfolioLink === event.portfolioLink;

        const withinWindow =
          Math.abs(new Date(g.createdAt) - new Date(event.createdAt)) <
          GROUP_WINDOW;

        return (
          sameEvent &&
          sameActor &&
          samePortfolio &&
          withinWindow &&
          ["PORTFOLIO_OPENED", "COMMENT_RECEIVED"].includes(event.event)
        );
      });

      if (group) {
        group.count += 1;

        // ⭐ keep latest timestamp for UI
        if (new Date(event.createdAt) > new Date(group.createdAt)) {
          group.createdAt = event.createdAt;
        }

        return;
      }

      groupedEvents.push({
        ...event,
        count: 1,
      });
    });

    //////////////////////////////////////////////////////
    // ⭐ FORMAT MESSAGE (BACKEND DOES UX MAGIC)
    //////////////////////////////////////////////////////

    const formatted = groupedEvents.map((e) => {
      let message = "";

      switch (e.event) {
        case "USER_REGISTERED":
          message = "You created an account";
          break;

        case "PORTFOLIO_CREATED":
          message = `You created portfolio ${e.portfolioLink}`;
          break;

        case "REVIEW_SHARED":
          message = `You shared ${e.portfolioLink} for review`;
          break;

        case "PORTFOLIO_OPENED":
          message = `${e.actorName || "Someone"} opened ${e.portfolioLink}${
            e.count > 1 ? ` ${e.count} times` : ""
          }`;
          break;

        case "COMMENT_ADDED":
          message = `You added a comment on ${e.portfolioLink}`;
          break;

        case "COMMENT_RECEIVED":
          message = `${
            e.actorName || e.metadata?.actorEmail || "Someone"
          } commented on ${e.portfolioLink} ${e.count > 1 ? ` ${e.count} times` : ""}`;
          break;

        case "PIN_ADDED":
          message = `You added feedback on ${e.portfolioLink}`;
          break;

        default:
          message = e.event;
      }

      return {
        message,
        event: e.event,
        createdAt: e.createdAt,
      };
    });

    //////////////////////////////////////////////////////
    // ⭐ GROUPING (timeline)
    //////////////////////////////////////////////////////

    const now = new Date();

    const startToday = new Date(now);
    startToday.setHours(0, 0, 0, 0);

    const startYesterday = new Date(startToday);
    startYesterday.setDate(startYesterday.getDate() - 1);

    const startWeek = new Date(startToday);
    startWeek.setDate(startWeek.getDate() - 7);

    const grouped = {
      today: [],
      yesterday: [],
      thisWeek: [],
      earlier: [],
    };

    formatted.forEach((e) => {
      const d = new Date(e.createdAt);

      if (d >= startToday) grouped.today.push(e);
      else if (d >= startYesterday) grouped.yesterday.push(e);
      else if (d >= startWeek) grouped.thisWeek.push(e);
      else grouped.earlier.push(e);
    });

    res.json(grouped);
  } catch (err) {
    console.error("Activity fetch error", err);
    res.status(500).json({ message: "Failed to fetch activity" });
  }
});

app.get("/api/review/:accessToken/activity", async (req, res) => {
  try {
    //////////////////////////////////////////////////////
    // ⭐ Resolve review from accessToken
    //////////////////////////////////////////////////////

    const review = await Review.findOne({
      accessToken: req.params.accessToken,
    })
      .populate("revieweeId", "_id name")
      .populate("reviewerId", "_id name")
      .populate("portfolioId", "portfolioLink");

    if (!review) {
      return res.status(404).json({ message: "Review not found" });
    }

    const reviewId = review._id;

    //////////////////////////////////////////////////////
    // ⭐ Viewer context
    //////////////////////////////////////////////////////

    const viewerId = req.userId
      ? new mongoose.Types.ObjectId(req.userId)
      : null;

    const isReviewer =
      viewerId && review.reviewerId && viewerId.equals(review.reviewerId._id);

    const isReviewee =
      viewerId && review.revieweeId && viewerId.equals(review.revieweeId._id);

    //////////////////////////////////////////////////////
    // ⭐ Fetch events for THIS review
    //////////////////////////////////////////////////////

    const events = await Event.aggregate([
      { $match: { reviewId } },

      // portfolio
      {
        $lookup: {
          from: "portfolio",
          localField: "portfolioId",
          foreignField: "_id",
          as: "portfolio",
        },
      },
      { $unwind: { path: "$portfolio", preserveNullAndEmptyArrays: true } },

      // actor
      {
        $lookup: {
          from: "user",
          localField: "metadata.actorId",
          foreignField: "_id",
          as: "actor",
        },
      },
      { $unwind: { path: "$actor", preserveNullAndEmptyArrays: true } },

      {
        $project: {
          event: 1,
          metadata: 1,
          createdAt: 1,
          portfolioLink: "$portfolio.portfolioLink",
          actorName: "$actor.name",
        },
      },

      { $sort: { createdAt: -1 } },
      { $limit: 50 },
    ]);

    //////////////////////////////////////////////////////
    // ⭐ GROUP EVENTS (5 min)
    //////////////////////////////////////////////////////

    const GROUP_WINDOW = 1000 * 60 * 5;
    const groupedEvents = [];

    events.forEach((event) => {
      const group = groupedEvents.find((g) => {
        const sameEvent = g.event === event.event;
        const sameActor = g.actorName === event.actorName;
        const samePortfolio = g.portfolioLink === event.portfolioLink;

        const withinWindow =
          Math.abs(new Date(g.createdAt) - new Date(event.createdAt)) <
          GROUP_WINDOW;

        return (
          sameEvent &&
          sameActor &&
          samePortfolio &&
          withinWindow &&
          ["PORTFOLIO_OPENED", "COMMENT_RECEIVED", "COMMENT_ADDED"].includes(
            event.event,
          )
        );
      });

      if (group) {
        group.count += 1;

        if (new Date(event.createdAt) > new Date(group.createdAt)) {
          group.createdAt = event.createdAt;
        }

        return;
      }

      groupedEvents.push({ ...event, count: 1 });
    });

    //////////////////////////////////////////////////////
    // ⭐ FORMAT (viewer aware)
    //////////////////////////////////////////////////////

    const formatted = groupedEvents.map((e) => {
      let message = "";

      const actorId = e.metadata?.actorId;
      const isActorViewer = viewerId && actorId && viewerId.equals(actorId);

      switch (e.event) {
        case "PORTFOLIO_OPENED":
          message = `${e.actorName || "Someone"} opened portfolio${
            e.count > 1 ? ` ${e.count} times` : ""
          }`;
          break;

        case "COMMENT_ADDED":
          message = `${
            isActorViewer ? "You" : e.actorName || "Someone"
          } added comment${e.count > 1 ? ` ${e.count} times` : ""}`;
          break;

        case "COMMENT_RECEIVED":
          message = `${
            isActorViewer
              ? "You"
              : e.actorName || e.metadata?.actorEmail || "Someone"
          } commented${e.count > 1 ? ` ${e.count} times` : ""}`;
          break;

        case "PIN_ADDED":
          message = `${isActorViewer ? "You" : e.actorName || "Someone"} added feedback`;
          break;

        case "REVIEW_SHARED":
          message = isReviewer
            ? "You shared review link"
            : "Review link shared";
          break;

        default:
          message = e.event;
      }

      return {
        message,
        event: e.event,
        createdAt: e.createdAt,
      };
    });

    //////////////////////////////////////////////////////
    // ⭐ TIME GROUPING
    //////////////////////////////////////////////////////

    const now = new Date();

    const startToday = new Date(now);
    startToday.setHours(0, 0, 0, 0);

    const startYesterday = new Date(startToday);
    startYesterday.setDate(startYesterday.getDate() - 1);

    const startWeek = new Date(startToday);
    startWeek.setDate(startWeek.getDate() - 7);

    const grouped = {
      today: [],
      yesterday: [],
      thisWeek: [],
      earlier: [],
    };

    formatted.forEach((e) => {
      const d = new Date(e.createdAt);

      if (d >= startToday) grouped.today.push(e);
      else if (d >= startYesterday) grouped.yesterday.push(e);
      else if (d >= startWeek) grouped.thisWeek.push(e);
      else grouped.earlier.push(e);
    });

    res.json(grouped);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Failed to fetch review activity" });
  }
});

app.get("/api/review/:accessToken/comments", async (req, res) => {
  try {
    //////////////////////////////////////////////////////
    // ⭐ Resolve reviewId from accessToken
    //////////////////////////////////////////////////////

    const review = await Review.findOne(
      { accessToken: req.params.accessToken },
      { _id: 1 },
    );

    if (!review) {
      return res.status(404).json({ message: "Review not found" });
    }

    //////////////////////////////////////////////////////
    // ⭐ Fetch comments (latest first)
    //////////////////////////////////////////////////////

    const comments = await Comment.aggregate([
      // Join pin → filter by review
      {
        $lookup: {
          from: "pin",
          localField: "pinId",
          foreignField: "_id",
          as: "pin",
        },
      },
      { $unwind: "$pin" },

      {
        $match: {
          "pin.reviewId": review._id,
        },
      },

      // Join author
      {
        $lookup: {
          from: "user",
          localField: "authorId",
          foreignField: "_id",
          as: "author",
        },
      },
      { $unwind: { path: "$author", preserveNullAndEmptyArrays: true } },

      //////////////////////////////////////////////////////
      // ⭐ FRONTEND READY SHAPE
      //////////////////////////////////////////////////////
      {
        $project: {
          _id: 1,
          text: "$content",
          author: {
            $ifNull: ["$author.name", "Guest reviewer"],
          },
          createdAt: 1,
        },
      },

      //////////////////////////////////////////////////////
      // ⭐ IMPORTANT → latest first
      //////////////////////////////////////////////////////
      { $sort: { createdAt: -1 } },
    ]);

    res.json(comments);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Failed to fetch comments" });
  }
});

app.listen(3000, () => {
  console.log("Server is running at port 3000");
});
