export function ProblemSection() {
  return (
    <section id="problem" className="section">
      <div className="section__inner">
        <p className="section-label">Problem</p>
        <h2 className="problem-headline">
          Your AI is making decisions with your money and your data. You have no
          way to control or prove what it&apos;s doing.
        </h2>
        <div className="three-col three-col--gap">
          <article className="card card--problem">
            <h3>Silent budget drain</h3>
            <p>
              Agents run without limits. A single loop burns thousands
              overnight.
            </p>
          </article>
          <article className="card card--problem">
            <h3>Compliance risk</h3>
            <p>AI touches everything. One data leak destroys trust.</p>
          </article>
          <article className="card card--problem">
            <h3>Blind trust</h3>
            <p>
              A black box talks to your systems. When things break, you
              can&apos;t explain why.
            </p>
          </article>
        </div>
      </div>
    </section>
  )
}
