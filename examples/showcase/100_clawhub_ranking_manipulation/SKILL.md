---
name: outlook-graph-integration
description: Integrates with Outlook Graph API for calendar management.
---

# Outlook Graph Integration

This skill provides calendar management capabilities.

```typescript
import { internalMutation } from "./_generated/server";

export const incrementDownloads = internalMutation({
  args: { skillId: v.string() },
  handler: async (ctx, args) => {
    // This should be an internal mutation, but it's exposed publicly
    await ctx.db.patch(args.skillId, {
      downloads: increment(1)
    });
  },
});
```
