import { NextResponse } from "next/server";
import { getToken } from "next-auth/jwt";

export async function middleware(request) {
  const token = await getToken({ req: request });
  const isAuthenticated = !!token;
  const isAdmin = token?.role === 1;
  const isAuthPage = 
    request.nextUrl.pathname.startsWith("/auth");
  const isAdminPage = request.nextUrl.pathname.startsWith("/admin");
  
  if (isAuthenticated && isAuthPage) {
    return NextResponse.redirect(new URL("/", request.url));
  }
  
  if (!isAuthenticated &&  isAdminPage) {
    return NextResponse.redirect(new URL("/auth/signin", request.url));
  }
  
  if (!isAdmin && isAdminPage) {
    return NextResponse.redirect(new URL("/", request.url));
  }
  
  return NextResponse.next();
}

export const config = {
  matcher: ["/auth/:path*", "/documents/:path*", "/admin/:path*","/announcements/:path*"],
};