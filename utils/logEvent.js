import { Event } from "../database/index.js";

export const logEvent = async ({
  userId,
  portfolioId = null,
  reviewId = null,
  event,
  metadata = {},
  batchWindowMinutes = 5,
}) => {
  try {
    // ⭐ batching for comments etc
    const since = new Date(Date.now() - batchWindowMinutes * 60000);

    const existing = await Event.findOne({
      userId,
      event,
      reviewId,
      createdAt: { $gte: since },
    });

    if (existing) {
      existing.count += 1;
      existing.createdAt = new Date();
      await existing.save();
      return;
    }

    await Event.create({
      userId,
      portfolioId,
      reviewId,
      event,
      metadata,
    });
  } catch (err) {
    console.error("Event log error", err);
  }
};
