export const slideCount = 12;

export interface Slide {
  id: number;
  title: string;
  subtitle: string;
}

export const slides: Slide[] = [
  { id: 1, title: "Positioning", subtitle: "What Connector is in one line" },
  { id: 2, title: "Problem", subtitle: "Why teams lose trust in agent systems" },
  { id: 3, title: "Why Now", subtitle: "The market timing behind the need" },
  { id: 4, title: "Entry Point", subtitle: "Where we land first" },
  { id: 5, title: "Solution", subtitle: "How Connector fixes the problem" },
  { id: 6, title: "Tech", subtitle: "What is actually under the hood" },
  { id: 7, title: "Business", subtitle: "What customers get and why they pay" },
  { id: 8, title: "Market Validation", subtitle: "Who needs this and why it is credible" },
  { id: 9, title: "Go-To-Market", subtitle: "How adoption compounds" },
  { id: 10, title: "Proof Plan", subtitle: "What design partners will validate" },
  { id: 11, title: "SWOT / Stage Truth", subtitle: "Strengths, weaknesses, opportunity, threat" },
  { id: 12, title: "Ask", subtitle: "What we want next" },
];
