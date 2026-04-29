export default function SiteFooter() {
	return (
		<footer className='border-t border-slate-200 bg-white/80 py-10 text-center text-xs text-slate-500'>
			<div className='mx-auto flex w-full max-w-6xl flex-col items-center gap-3 px-6'>
				<div className='text-sm font-semibold text-slate-700'>
					Encrypted Social Space
				</div>
				<div className='max-w-lg'>
					Secure collaboration for requests, responses, and real-time messaging
					with encrypted data at every step.
				</div>
				<div className='flex flex-wrap justify-center gap-4 text-xs font-semibold uppercase tracking-[0.2em] text-slate-400'>
					<span>Privacy</span>
					<span>Security</span>
					<span>Support</span>
				</div>
			</div>
		</footer>
	);
}
