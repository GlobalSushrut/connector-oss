use leptos::prelude::*;

use crate::components::operator::cards::OpMetricCard;

#[component]
pub fn OpSparklineGrid(
    #[prop(optional)] metrics: Option<Vec<(String, String, Vec<f64>)>>,
) -> impl IntoView {
    let metrics = metrics.unwrap_or_default();
    if metrics.is_empty() {
        return view! { <div></div> }.into_any();
    }
    view! {
        <div class="mon-metric-grid">
            {metrics.into_iter().map(|(label, value, spark)| view! {
                <OpMetricCard label=label value=value sparkline=spark />
            }).collect_view()}
        </div>
    }
    .into_any()
}
