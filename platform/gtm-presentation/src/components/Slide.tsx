import React from 'react';
import type { ReactNode } from 'react';

interface SlideProps {
  children: ReactNode;
  slideNumber?: number;
  totalSlides?: number;
}

export const Slide: React.FC<SlideProps> = ({ children, slideNumber, totalSlides }) => {
  return (
    <div className="slide-container w-full h-full bg-slate-900 text-slate-50 flex flex-col items-center justify-center relative overflow-hidden">
      {/* Background decorations */}
      <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-blue-600 via-indigo-500 to-purple-600 z-10" />
      <div className="absolute -top-40 -right-40 w-96 h-96 rounded-full bg-blue-500 opacity-10 blur-3xl" />
      <div className="absolute -bottom-40 -left-40 w-96 h-96 rounded-full bg-indigo-500 opacity-10 blur-3xl" />
      
      {/* Main Content Area - 16:9 Aspect Ratio Container */}
      <div className="relative z-10 flex h-[780px] w-[1380px] max-h-full max-w-full flex-col rounded-2xl border border-slate-800/50 bg-slate-900/60 px-8 py-6 shadow-2xl backdrop-blur-sm max-xl:scale-[0.78] max-xl:origin-center max-lg:px-6 max-lg:py-5">
        {children}
        
        {/* Footer */}
        <div className="absolute bottom-3 left-8 right-8 flex justify-between items-center text-[9px] font-medium tracking-wider text-slate-500">
          <div className="flex items-center space-x-2">
            <div className="h-2.5 w-2.5 rounded-sm bg-blue-500"></div>
            <span>CONNECTOR</span>
          </div>
          {slideNumber !== undefined && totalSlides !== undefined && (
            <div className="flex items-center space-x-4">
              <span>INTERNAL WORKFLOW CONTROL</span>
              <span>•</span>
              <span>{slideNumber} / {totalSlides}</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export const SlideTitle: React.FC<{ children: ReactNode }> = ({ children }) => (
  <h1 className="mb-4 bg-gradient-to-r from-white to-slate-400 bg-clip-text text-[30px] font-extrabold tracking-tight text-transparent xl:text-4xl">
    <span className="mr-2 text-blue-500">⚡</span>
    {children}
  </h1>
);

export const SlideContent: React.FC<{ children: ReactNode }> = ({ children }) => (
  <div className="flex flex-1 flex-col justify-center space-y-2.5 text-sm leading-snug text-slate-300 xl:text-base">
    {children}
  </div>
);

export const Highlight: React.FC<{ children: ReactNode }> = ({ children }) => (
  <span className="text-white font-bold">{children}</span>
);
