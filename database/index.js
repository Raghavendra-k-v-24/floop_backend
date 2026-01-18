import dotenv from "dotenv";
import mongoose from "mongoose";

dotenv.config();

const MONGODB_PASS = process.env.MONGODB_PASS;

mongoose.connect(
  `mongodb+srv://raghavendrakv23:${MONGODB_PASS}@cluster0.qj6ks.mongodb.net/floop_new`,
);

//schemas
const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      index: true,
    },
    password: {
      type: String,
      required: true,
    },
    role: {
      type: [String],
      enum: ["reviewee", "reviewer"],
      default: [],
    },
    status: {
      type: String,
      enum: ["active", "suspended"],
      default: "active",
    },
  },
  { timestamps: true },
);

const portfolioSchema = new mongoose.Schema(
  {
    ownerUserId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      index: true,
    },
    createdByUserId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    portfolioLink: {
      type: String,
      required: true,
    },
    isOpened: {
      type: Boolean,
      default: false,
    },
    openCount: {
      type: Number,
      default: 0,
    },
    lastOpenedAt: {
      type: Date,
    },
  },
  { timestamps: true },
);

const reviewSchema = new mongoose.Schema(
  {
    portfolioId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Portfolio",
      required: true,
      index: true,
    },
    revieweeId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    createdByUserId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    reviewerId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      default: null,
      index: true,
    },
    goals: {
      type: [String],
      default: [],
    },
    invitedReviewerEmail: {
      type: String,
      lowercase: true,
      index: true,
    },
    accessType: {
      type: String,
      enum: ["view", "comment"],
      default: "view",
    },
    accessToken: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    intent: {
      type: String,
      enum: ["reviewee", "reviewer"],
      required: true,
    },
  },
  { timestamps: true },
);

const pinSchema = new mongoose.Schema(
  {
    reviewId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Review",
      required: true,
      index: true,
    },

    pageUrl: {
      type: String,
      required: true,
    },

    position: {
      x: {
        type: Number,
        required: true,
      },
      y: {
        type: Number,
        required: true,
      },
    },

    selector: {
      type: String,
    },

    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
  },
  { timestamps: { createdAt: true, updatedAt: false } },
);

const commentSchema = new mongoose.Schema(
  {
    pinId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Pin",
      required: true,
      index: true,
    },

    authorId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },

    content: {
      type: String,
      required: true,
      trim: true,
    },

    parentCommentId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Comment",
      default: null,
    },
  },
  { timestamps: true },
);

const eventSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      index: true,
    },

    portfolioId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Portfolio",
      index: true,
    },

    reviewId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Review",
    },

    event: {
      type: String,
      required: true,
      // e.g. USER_REGISTERED, REVIEW_INVITED, COMMENT_ADDED
    },

    metadata: {
      type: mongoose.Schema.Types.Mixed,
    },
  },
  { timestamps: { createdAt: true, updatedAt: false } },
);

//model
const User = mongoose.model("user", userSchema, "user");

const Portfolio = mongoose.model("portfolio", portfolioSchema, "portfolio");

const Review = mongoose.model("review", reviewSchema, "review");

const Pin = mongoose.model("pin", pinSchema, "pin");

const Comment = mongoose.model("comment", commentSchema, "comment");

const Event = mongoose.model("event", eventSchema, "event");

export { User, Portfolio, Review, Pin, Comment, Event };
