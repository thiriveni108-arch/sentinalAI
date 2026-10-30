export const Component = () => {
  return (
    <div className="site-background pointer-events-none absolute inset-0 -z-10 min-h-full bg-white" aria-hidden="true">
      <div className="site-background-grid absolute inset-0 bg-[linear-gradient(to_right,#f0f0f0_1px,transparent_1px),linear-gradient(to_bottom,#f0f0f0_1px,transparent_1px)] bg-[size:6rem_4rem]" />
      <div className="site-background-glow fixed right-0 top-0 h-[300px] w-[430px]" />
    </div>
  );
};
