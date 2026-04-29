export default function Home() {
	return (
		<div className='relative min-h-screen overflow-hidden bg-[radial-gradient(1200px_600px_at_50%_-10%,oklch(0.24_0.08_255/0.65),transparent),linear-gradient(180deg,oklch(0.16_0.05_255),oklch(0.12_0.04_255))] text-foreground'>
			<div className='pointer-events-none absolute inset-0'>
				<div className='absolute -top-32 left-1/2 h-72 w-72 -translate-x-1/2 rounded-full bg-sky-500/30 blur-3xl animate-float' />
				<div className='absolute right-12 top-24 h-40 w-40 rounded-3xl bg-blue-400/30 blur-2xl animate-float-delayed' />
				<div className='absolute bottom-0 left-8 h-56 w-56 rounded-full bg-cyan-500/20 blur-3xl' />
			</div>

			<main className='relative mx-auto flex w-full max-w-6xl flex-1 flex-col px-8 pb-24 pt-14 sm:px-10 lg:px-16'>
				<section className='mx-auto flex w-full max-w-3xl flex-col items-center gap-6 text-center'>
					<div className='flex items-center gap-3 rounded-full border border-border bg-card/70 px-4 py-2 text-xs font-semibold uppercase tracking-[0.2em] text-muted-foreground shadow-sm'>
						SkillShare
					</div>
					<h1 className='text-balance  text-4xl leading-tight sm:text-5xl md:text-6xl'>
						Share needs, unlock help, keep every detail encrypted.
					</h1>
					<p className='text-balance  text-base text-muted-foreground sm:text-lg'>
						Build trusted connections with end-to-end protected profiles,
						requests, and direct messages. Every sensitive field stays locked
						with asymmetric encryption.
					</p>
					<div className='flex w-full flex-col items-center gap-3 sm:flex-row sm:justify-center'>
						<a
							className='inline-flex h-12 w-full items-center justify-center rounded-full bg-primary px-6 text-sm font-semibold text-primary-foreground shadow-lg shadow-black/20 transition-transform hover:-translate-y-0.5 sm:w-auto'
							href='/auth/signup'
						>
							Create your space
						</a>
						<a
							className='inline-flex h-12 w-full items-center justify-center rounded-full border border-input bg-card/60 px-6 text-sm font-semibold text-foreground transition-colors hover:bg-card sm:w-auto'
							href='/feed'
						>
							Explore the feed
						</a>
					</div>
					<div className='flex flex-wrap justify-center gap-6 text-sm text-muted-foreground'>
						<div className='flex items-center gap-2'>
							<span className='h-2 w-2 rounded-full bg-emerald-400' />
							Private profiles, public outcomes
						</div>
						<div className='flex items-center gap-2'>
							<span className='h-2 w-2 rounded-full bg-sky-400' />
							Real-time encrypted messaging
						</div>
					</div>
				</section>

				<section className='mt-16 grid gap-6 md:grid-cols-3'>
					{[
						{
							title: "Encrypted requests",
							desc: "Post needs without revealing sensitive details to the database.",
						},
						{
							title: "Trusted help",
							desc: "Verify replies with MAC validation before anything is shown.",
						},
						{
							title: "Safe direct messages",
							desc: "Double-encrypted DMs protect both sender and recipient.",
						},
					].map((item) => (
						<div
							key={item.title}
							className='group rounded-3xl border border-border/70 bg-card/70 p-6 shadow-lg shadow-black/20 backdrop-blur'
						>
							<h3 className=' text-xl text-foreground'>{item.title}</h3>
							<p className='mt-3 text-sm text-muted-foreground'>{item.desc}</p>
							<div className='mt-6 h-1 w-12 rounded-full bg-sky-400 transition-all group-hover:w-20' />
						</div>
					))}
				</section>

				<section className='mt-16 grid gap-6 lg:grid-cols-[1.2fr_0.8fr]'>
					<div className='rounded-[32px] border border-border/80 bg-card/80 p-8 shadow-xl shadow-black/20'>
						<h2 className=' text-3xl text-foreground'>
							Centralized trust, decentralized access.
						</h2>
						<p className='mt-4 text-sm text-muted-foreground sm:text-base'>
							Invite partners, coordinate support, and keep private data sealed
							with ECC and RSA encryption. Your community sees what you approve,
							and nothing more.
						</p>
						<div className='mt-8 grid gap-4 sm:grid-cols-2'>
							{[
								"Asymmetric encryption",
								"Role-based access",
								"HMAC integrity",
								"Secure sessions",
							].map((label) => (
								<div
									key={label}
									className='rounded-2xl border border-border/60 bg-muted/60 px-4 py-3 text-sm font-semibold text-foreground'
								>
									{label}
								</div>
							))}
						</div>
					</div>
					<div className='rounded-[32px] border border-sky-500/40 bg-linear-to-br from-sky-500/10 via-blue-500/10 to-emerald-500/10 p-8 shadow-lg shadow-black/20'>
						<div className='text-xs font-semibold uppercase tracking-[0.3em] text-sky-300'>
							Live now
						</div>
						<h3 className='mt-4  text-2xl text-foreground'>
							From onboarding to a verified reply in minutes.
						</h3>
						<ul className='mt-6 space-y-3 text-sm text-muted-foreground'>
							<li>1. Create an encrypted profile.</li>
							<li>2. Post a request with safe metadata.</li>
							<li>3. Chat securely with responders.</li>
						</ul>
						<a
							className='mt-8 inline-flex items-center text-sm font-semibold text-sky-300 hover:text-sky-200'
							href='/auth/login'
						>
							Sign in to continue
						</a>
					</div>
				</section>

				<section className='mt-20 rounded-[36px] border border-border/70 bg-slate-950 px-8 py-12 text-white shadow-2xl shadow-black/30'>
					<div className='mx-auto flex max-w-3xl flex-col items-center gap-6 text-center'>
						<h2 className=' text-3xl sm:text-4xl'>
							Meet your next collaborator in a safer space.
						</h2>
						<p className='text-sm text-slate-300 sm:text-base'>
							Launch your encrypted community hub with a single account, invite
							trusted members, and keep every conversation protected.
						</p>
						<div className='flex w-full flex-col items-center gap-3 sm:flex-row sm:justify-center'>
							<a
								className='inline-flex h-12 w-full items-center justify-center rounded-full bg-sky-300 px-6 text-sm font-semibold text-slate-900 transition-transform hover:-translate-y-0.5 sm:w-auto'
								href='/auth/signup'
							>
								Start for free
							</a>
							<a
								className='inline-flex h-12 w-full items-center justify-center rounded-full border border-white/20 px-6 text-sm font-semibold text-white/90 hover:bg-white/10 sm:w-auto'
								href='/dashboard'
							>
								View dashboard
							</a>
						</div>
					</div>
				</section>
			</main>
		</div>
	);
}
