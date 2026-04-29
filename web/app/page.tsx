
export default function Home() {
	return (
		<div
			className='relative min-h-screen overflow-hidden bg-[radial-gradient(1200px_600px_at_50%_-10%,#f7f3ec,transparent),linear-gradient(180deg,#fbf9f5,#f2efe9)] text-slate-900'
		>
			<div className='pointer-events-none absolute inset-0'>
				<div className='absolute -top-32 left-1/2 h-72 w-72 -translate-x-1/2 rounded-full bg-amber-200/50 blur-3xl animate-float' />
				<div className='absolute right-12 top-24 h-40 w-40 rounded-3xl bg-emerald-200/70 blur-2xl animate-float-delayed' />
				<div className='absolute bottom-0 left-8 h-56 w-56 rounded-full bg-orange-200/50 blur-3xl' />
			</div>

			<main className='relative mx-auto flex w-full max-w-6xl flex-1 flex-col px-6 pb-20 pt-10'>
				<section className='mx-auto flex w-full max-w-3xl flex-col items-center gap-6 text-center'>
					<div className='flex items-center gap-3 rounded-full border border-slate-200 bg-white/80 px-4 py-2 text-xs font-semibold uppercase tracking-[0.2em] text-slate-600 shadow-sm'>
						SkillShare
					</div>
					<h1 className='text-balance  text-4xl leading-tight sm:text-5xl md:text-6xl'>
						Share needs, unlock help, keep every detail encrypted.
					</h1>
					<p className='text-balance  text-base text-slate-600 sm:text-lg'>
						Build trusted connections with end-to-end protected profiles,
						requests, and direct messages. Every sensitive field stays locked
						with asymmetric encryption.
					</p>
					<div className='flex w-full flex-col items-center gap-3 sm:flex-row sm:justify-center'>
						<a
							className='inline-flex h-12 w-full items-center justify-center rounded-full bg-slate-900 px-6 text-sm font-semibold text-white shadow-lg shadow-slate-900/20 transition-transform hover:-translate-y-0.5 sm:w-auto'
							href='/auth/signup'
						>
							Create your space
						</a>
						<a
							className='inline-flex h-12 w-full items-center justify-center rounded-full border border-slate-300 bg-white/80 px-6 text-sm font-semibold text-slate-700 transition-colors hover:bg-white sm:w-auto'
							href='/feed'
						>
							Explore the feed
						</a>
					</div>
					<div className='flex flex-wrap justify-center gap-6 text-sm text-slate-500'>
						<div className='flex items-center gap-2'>
							<span className='h-2 w-2 rounded-full bg-emerald-500' />
							Private profiles, public outcomes
						</div>
						<div className='flex items-center gap-2'>
							<span className='h-2 w-2 rounded-full bg-amber-500' />
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
							className='group rounded-3xl border border-white/60 bg-white/70 p-6 shadow-lg shadow-slate-200/60 backdrop-blur'
						>
							<h3 className=' text-xl text-slate-900'>{item.title}</h3>
							<p className='mt-3 text-sm text-slate-600'>{item.desc}</p>
							<div className='mt-6 h-1 w-12 rounded-full bg-amber-400 transition-all group-hover:w-20' />
						</div>
					))}
				</section>

				<section className='mt-16 grid gap-6 lg:grid-cols-[1.2fr_0.8fr]'>
					<div className='rounded-[32px] border border-slate-200 bg-white/80 p-8 shadow-xl shadow-slate-200/70'>
						<h2 className=' text-3xl text-slate-900'>
							Centralized trust, decentralized access.
						</h2>
						<p className='mt-4 text-sm text-slate-600 sm:text-base'>
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
									className='rounded-2xl border border-slate-200/70 bg-slate-50 px-4 py-3 text-sm font-semibold text-slate-700'
								>
									{label}
								</div>
							))}
						</div>
					</div>
					<div className='rounded-[32px] border border-amber-200 bg-linear-to-br from-amber-50 via-white to-emerald-50 p-8 shadow-lg shadow-amber-100'>
						<div className='text-xs font-semibold uppercase tracking-[0.3em] text-amber-700'>
							Live now
						</div>
						<h3 className='mt-4  text-2xl text-slate-900'>
							From onboarding to a verified reply in minutes.
						</h3>
						<ul className='mt-6 space-y-3 text-sm text-slate-600'>
							<li>1. Create an encrypted profile.</li>
							<li>2. Post a request with safe metadata.</li>
							<li>3. Chat securely with responders.</li>
						</ul>
						<a
							className='mt-8 inline-flex items-center text-sm font-semibold text-emerald-700'
							href='/auth/login'
						>
							Sign in to continue
						</a>
					</div>
				</section>

				<section className='mt-20 rounded-[36px] border border-slate-200 bg-slate-900 px-8 py-12 text-white shadow-2xl shadow-slate-900/20'>
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
								className='inline-flex h-12 w-full items-center justify-center rounded-full bg-amber-300 px-6 text-sm font-semibold text-slate-900 transition-transform hover:-translate-y-0.5 sm:w-auto'
								href='/auth/signup'
							>
								Start for free
							</a>
							<a
								className='inline-flex h-12 w-full items-center justify-center rounded-full border border-white/30 px-6 text-sm font-semibold text-white/90 hover:bg-white/10 sm:w-auto'
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
