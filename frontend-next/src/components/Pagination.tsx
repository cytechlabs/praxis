import React from 'react';
import { ChevronLeft, ChevronRight } from 'lucide-react';

interface PaginationProps {
  offset: number;
  limit: number;
  total: number;
  onPageChange: (newOffset: number) => void;
}

const Pagination: React.FC<PaginationProps> = ({ offset, limit, total, onPageChange }) => {
  const currentPage = Math.floor(offset / limit) + 1;
  const totalPages = Math.max(1, Math.ceil(total / limit));
  const start = total === 0 ? 0 : offset + 1;
  const end = Math.min(offset + limit, total);

  return (
    <div className="flex items-center justify-between mt-4 text-sm text-gray-400">
      <span>
        Showing {start}–{end} of {total}
      </span>
      <div className="flex items-center gap-2">
        <button
          onClick={() => onPageChange(offset - limit)}
          disabled={offset <= 0}
          className="flex items-center gap-1 px-3 py-1 border border-gray-700 rounded hover:bg-gray-800 disabled:opacity-40 disabled:cursor-not-allowed"
        >
          <ChevronLeft size={14} /> Previous
        </button>
        <span className="px-2">
          Page {currentPage} of {totalPages}
        </span>
        <button
          onClick={() => onPageChange(offset + limit)}
          disabled={offset + limit >= total}
          className="flex items-center gap-1 px-3 py-1 border border-gray-700 rounded hover:bg-gray-800 disabled:opacity-40 disabled:cursor-not-allowed"
        >
          Next <ChevronRight size={14} />
        </button>
      </div>
    </div>
  );
};

export default Pagination;
