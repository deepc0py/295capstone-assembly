/**
 * Mark False Positive Button Component
 * Week 5: Simple FP marking (no complex patterns or confidence scoring)
 */

import { useState } from 'react';
import { Button } from '@/components/ui/button';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from '@/components/ui/alert-dialog';
import { useToast } from '@/hooks/use-toast';
import { XCircle, Check } from 'lucide-react';

interface MarkFalsePositiveButtonProps {
  findingId: string;
  currentStatus?: string;
  onStatusChanged?: () => void;
  size?: 'sm' | 'default' | 'lg';
}

export function MarkFalsePositiveButton({
  findingId,
  currentStatus,
  onStatusChanged,
  size = 'sm',
}: MarkFalsePositiveButtonProps) {
  const [isLoading, setIsLoading] = useState(false);
  const { toast } = useToast();

  const handleMarkAsFalsePositive = async () => {
    setIsLoading(true);

    try {
      const token = localStorage.getItem('venti_auth_token');
      const API_BASE = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

      const response = await fetch(`${API_BASE}/api/finding/${findingId}/status`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          new_status: 'false_positive',
          change_reason: 'Marked as false positive by analyst',
        }),
      });

      if (!response.ok) {
        throw new Error('Failed to mark as false positive');
      }

      toast({
        title: 'Marked as False Positive',
        description: 'This finding will be hidden from future views.',
        duration: 3000,
      });

      // Trigger refresh
      if (onStatusChanged) {
        onStatusChanged();
      }
    } catch (error) {
      console.error('Error marking as FP:', error);
      toast({
        title: 'Error',
        description: 'Failed to mark as false positive. Please try again.',
        variant: 'destructive',
      });
    } finally {
      setIsLoading(false);
    }
  };

  const handleUnmark = async () => {
    setIsLoading(true);

    try {
      const token = localStorage.getItem('venti_auth_token');
      const API_BASE = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

      const response = await fetch(`${API_BASE}/api/finding/${findingId}/status`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          new_status: 'new',
          change_reason: 'Unmarked false positive - needs review',
        }),
      });

      if (!response.ok) {
        throw new Error('Failed to unmark false positive');
      }

      toast({
        title: 'Unmarked False Positive',
        description: 'This finding is now visible again.',
        duration: 3000,
      });

      if (onStatusChanged) {
        onStatusChanged();
      }
    } catch (error) {
      console.error('Error unmarking FP:', error);
      toast({
        title: 'Error',
        description: 'Failed to unmark false positive.',
        variant: 'destructive',
      });
    } finally {
      setIsLoading(false);
    }
  };

  // If already marked as FP, show unmark button
  if (currentStatus === 'false_positive') {
    return (
      <AlertDialog>
        <AlertDialogTrigger asChild>
          <Button variant="outline" size={size} disabled={isLoading}>
            <Check className="w-4 h-4 mr-2" />
            False Positive
          </Button>
        </AlertDialogTrigger>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Unmark False Positive?</AlertDialogTitle>
            <AlertDialogDescription>
              This will restore the finding to "New" status and make it visible again.
              Are you sure you want to unmark this as a false positive?
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={handleUnmark}>
              Unmark
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    );
  }

  // Show mark as FP button
  return (
    <AlertDialog>
      <AlertDialogTrigger asChild>
        <Button variant="outline" size={size} disabled={isLoading}>
          <XCircle className="w-4 h-4 mr-2" />
          Mark as False Positive
        </Button>
      </AlertDialogTrigger>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Mark as False Positive?</AlertDialogTitle>
          <AlertDialogDescription>
            This finding will be hidden from your findings list and excluded from AI agent analysis.
            You can always unmark it later if needed.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel>Cancel</AlertDialogCancel>
          <AlertDialogAction onClick={handleMarkAsFalsePositive}>
            Mark as False Positive
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
