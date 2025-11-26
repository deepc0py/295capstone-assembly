"use client";

import { useState, useEffect } from "react";
import { Send, Loader2, MessageSquare, User } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { cn } from "@/lib/utils";
import { toast } from "sonner";
import { getTeamMembers } from "./AssigneeSelector";

interface Comment {
  id: string;
  finding_id: string;
  author: string;
  comment: string;
  comment_type: "note" | "analysis" | "remediation" | "escalation" | "resolution";
  is_internal: boolean;
  mentions: string[];
  created_at: string;
  updated_at: string;
}

interface CommentsSectionProps {
  findingId: string;
  initialComments?: Comment[];
  onCommentAdded?: (comment: Comment) => void;
}

const COMMENT_TYPES = [
  { value: "note", label: "Note", color: "bg-gray-100 text-gray-700" },
  { value: "analysis", label: "Analysis", color: "bg-blue-100 text-blue-700" },
  { value: "remediation", label: "Remediation", color: "bg-green-100 text-green-700" },
  { value: "escalation", label: "Escalation", color: "bg-orange-100 text-orange-700" },
  { value: "resolution", label: "Resolution", color: "bg-purple-100 text-purple-700" },
];

const getInitials = (email: string) => {
  const name = email.split("@")[0];
  return name
    .split(".")
    .map((n) => n[0])
    .join("")
    .toUpperCase()
    .slice(0, 2);
};

const getColorForAuthor = (author: string) => {
  const colors = [
    "bg-blue-500",
    "bg-green-500",
    "bg-purple-500",
    "bg-orange-500",
    "bg-pink-500",
    "bg-indigo-500",
  ];
  const index = author.split("").reduce((acc, char) => acc + char.charCodeAt(0), 0) % colors.length;
  return colors[index];
};

export const CommentsSection = ({
  findingId,
  initialComments = [],
  onCommentAdded,
}: CommentsSectionProps) => {
  const [comments, setComments] = useState<Comment[]>(initialComments);
  const [newComment, setNewComment] = useState("");
  const [commentType, setCommentType] = useState<Comment["comment_type"]>("note");
  const [isInternal, setIsInternal] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  // Load comments on mount
  useEffect(() => {
    loadComments();
  }, [findingId]);

  const loadComments = async () => {
    try {
      const response = await fetch(
        `http://localhost:8000/api/finding/${findingId}/comments?include_internal=true`,
        {
          headers: {
            // TODO: Add JWT token from auth context
          },
        }
      );

      if (response.ok) {
        const data = await response.json();
        setComments(data.comments || []);
      }
    } catch (error) {
      console.error("Failed to load comments:", error);
    } finally {
      setIsLoading(false);
    }
  };

  const handleSubmitComment = async () => {
    if (!newComment.trim()) {
      toast.error("Please enter a comment");
      return;
    }

    setIsSubmitting(true);

    try {
      // Extract @mentions from comment
      const mentionRegex = /@(\w+@\w+\.\w+)/g;
      const mentions = Array.from(newComment.matchAll(mentionRegex)).map((match) => match[1]);

      const response = await fetch(`http://localhost:8000/api/finding/${findingId}/comment`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          // TODO: Add JWT token from auth context
        },
        body: JSON.stringify({
          comment: newComment,
          comment_type: commentType,
          is_internal: isInternal,
          mentions,
        }),
      });

      if (!response.ok) {
        throw new Error(`Failed to add comment: ${response.statusText}`);
      }

      const data = await response.json();

      setComments([...comments, data]);
      setNewComment("");
      setCommentType("note");
      setIsInternal(false);

      if (onCommentAdded) {
        onCommentAdded(data);
      }

      toast.success("Comment added successfully");
    } catch (error) {
      console.error("Failed to add comment:", error);
      toast.error("Failed to add comment. Please try again.");
    } finally {
      setIsSubmitting(false);
    }
  };

  const formatTimestamp = (timestamp: string) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMins < 1) return "just now";
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    if (diffDays < 7) return `${diffDays}d ago`;
    return date.toLocaleDateString();
  };

  const highlightMentions = (text: string) => {
    const mentionRegex = /(@\w+@\w+\.\w+)/g;
    const parts = text.split(mentionRegex);

    return parts.map((part, index) => {
      if (part.match(mentionRegex)) {
        return (
          <span key={index} className="bg-blue-100 text-blue-700 px-1 rounded">
            {part}
          </span>
        );
      }
      return <span key={index}>{part}</span>;
    });
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <MessageSquare className="h-4 w-4 text-muted-foreground" />
        <h3 className="text-sm font-semibold">
          Comments {comments.length > 0 && `(${comments.length})`}
        </h3>
      </div>

      {/* Comments list */}
      <div className="space-y-3 max-h-96 overflow-y-auto">
        {isLoading ? (
          <div className="flex items-center justify-center py-8">
            <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
          </div>
        ) : comments.length === 0 ? (
          <div className="text-center py-8 text-sm text-muted-foreground">
            No comments yet. Be the first to add one!
          </div>
        ) : (
          comments.map((comment) => {
            const typeConfig = COMMENT_TYPES.find((t) => t.value === comment.comment_type);
            return (
              <div key={comment.id} className="flex gap-3 p-3 rounded-lg bg-gray-50 border">
                <Avatar className="h-8 w-8 flex-shrink-0">
                  <AvatarFallback
                    className={cn("text-xs text-white", getColorForAuthor(comment.author))}
                  >
                    {getInitials(comment.author)}
                  </AvatarFallback>
                </Avatar>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-sm font-medium">{comment.author}</span>
                    {typeConfig && (
                      <Badge variant="outline" className={cn("text-xs", typeConfig.color)}>
                        {typeConfig.label}
                      </Badge>
                    )}
                    {comment.is_internal && (
                      <Badge variant="outline" className="text-xs bg-gray-200 text-gray-700">
                        Internal
                      </Badge>
                    )}
                    <span className="text-xs text-muted-foreground ml-auto">
                      {formatTimestamp(comment.created_at)}
                    </span>
                  </div>
                  <div className="text-sm text-gray-700 whitespace-pre-wrap break-words">
                    {highlightMentions(comment.comment)}
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* New comment form */}
      <div className="space-y-3 border-t pt-4">
        <div className="flex gap-2">
          <Select
            value={commentType}
            onValueChange={(value: Comment["comment_type"]) => setCommentType(value)}
          >
            <SelectTrigger className="w-40">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {COMMENT_TYPES.map((type) => (
                <SelectItem key={type.value} value={type.value}>
                  <div className="flex items-center gap-2">
                    <div className={cn("h-2 w-2 rounded-full", type.color)} />
                    {type.label}
                  </div>
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <label className="flex items-center gap-2 text-sm text-muted-foreground">
            <input
              type="checkbox"
              checked={isInternal}
              onChange={(e) => setIsInternal(e.target.checked)}
              className="rounded border-gray-300"
            />
            Internal only
          </label>
        </div>

        <Textarea
          value={newComment}
          onChange={(e) => setNewComment(e.target.value)}
          placeholder="Add a comment... Use @email to mention someone"
          rows={3}
          disabled={isSubmitting}
          className="resize-none"
        />

        <div className="flex justify-between items-center">
          <div className="text-xs text-muted-foreground">
            Tip: Use @email to mention team members
          </div>
          <Button
            onClick={handleSubmitComment}
            disabled={isSubmitting || !newComment.trim()}
            size="sm"
          >
            {isSubmitting ? (
              <>
                <Loader2 className="h-3 w-3 mr-2 animate-spin" />
                Sending...
              </>
            ) : (
              <>
                <Send className="h-3 w-3 mr-2" />
                Comment
              </>
            )}
          </Button>
        </div>
      </div>
    </div>
  );
};

/**
 * Compact comment count badge for tables/lists
 */
export const CommentCountBadge = ({ count }: { count: number }) => {
  if (count === 0) {
    return (
      <div className="flex items-center gap-1 text-muted-foreground">
        <MessageSquare className="h-3 w-3" />
        <span className="text-xs">0</span>
      </div>
    );
  }

  return (
    <div className="flex items-center gap-1 text-blue-600">
      <MessageSquare className="h-3 w-3" />
      <span className="text-xs font-medium">{count}</span>
    </div>
  );
};
