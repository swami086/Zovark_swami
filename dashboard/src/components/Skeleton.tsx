import React from 'react';

interface SkeletonProps {
    className?: string;
}

export const Skeleton: React.FC<SkeletonProps> = ({ className }) => {
    return (
        <div className={`animate-pulse bg-slate-800/50 rounded ${className}`} />
    );
};

export const TableRowSkeleton = () => (
    <div className="flex items-center space-x-4 px-6 py-4 border-b border-slate-700/50">
        <Skeleton className="h-4 w-12" />
        <Skeleton className="h-4 flex-1" />
        <Skeleton className="h-4 w-24" />
        <Skeleton className="h-6 w-20 rounded-full" />
        <Skeleton className="h-4 w-24" />
        <Skeleton className="h-4 w-16" />
    </div>
);

export const CardSkeleton = () => (
    <div className="bg-[#1E293B] border border-slate-700/50 rounded-xl p-5 space-y-3">
        <div className="flex items-center space-x-2">
            <Skeleton className="w-4 h-4 rounded" />
            <Skeleton className="w-24 h-3" />
        </div>
        <Skeleton className="h-8 w-16" />
    </div>
);
