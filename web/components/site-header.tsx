import Link from "next/link";

export default function SiteHeader() {
	return (
		<header className='sticky top-0 z-40 border-b border-white/60 bg-white/80 backdrop-blur'>
			<div className='mx-auto flex w-full max-w-6xl items-center justify-between gap-6 px-6 py-4'>
				<Link href='/' className='text-lg font-semibold text-slate-900'>
					SkillShare
				</Link>
				<nav className='hidden items-center gap-6 text-sm font-semibold text-slate-600 md:flex'>
					<Link href='/feed' className='transition-colors hover:text-slate-900'>
						Feed
					</Link>
					<Link
						href='/messages'
						className='transition-colors hover:text-slate-900'
					>
						Messages
					</Link>
					<Link
						href='/dashboard'
						className='transition-colors hover:text-slate-900'
					>
						Dashboard
					</Link>
					<Link
						href='/profile'
						className='transition-colors hover:text-slate-900'
					>
						Profile
					</Link>
				</nav>
				<div className='flex items-center gap-2'>
					<Link
						href='/auth/login'
						className='hidden rounded-full border border-slate-200 px-4 py-2 text-xs font-semibold text-slate-700 transition-colors hover:bg-slate-100 sm:inline-flex'
					>
						Sign in
					</Link>
					<Link
						href='/auth/signup'
						className='inline-flex rounded-full bg-slate-900 px-4 py-2 text-xs font-semibold text-white shadow-lg shadow-slate-900/20 transition-transform hover:-translate-y-0.5'
					>
						Get started
					</Link>
				</div>
			</div>
		</header>
	);
}
