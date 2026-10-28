import { useLayoutEffect, useRef, type ReactNode } from "react";
import { createPortal } from "react-dom";

type Props = {
  open: boolean;
  onDismiss: () => void;
  labelledBy: string;
  className?: string;
  initialFocus?: string;
  dismissOnBackdrop?: boolean;
  children: ReactNode;
};
type ActiveModal = {
  dialog: HTMLDialogElement;
  returnFocus: HTMLElement | null;
};
const activeModals: ActiveModal[] = [];
let closingModal: ActiveModal | null = null;
let unlockPage: (() => void) | null = null;

function lockPage() {
  const body = document.body;
  const root = document.documentElement;
  const scrollX = window.scrollX;
  const scrollY = window.scrollY;
  const scrollbar = window.innerWidth - root.clientWidth;
  const padding = parseFloat(getComputedStyle(body).paddingRight) || 0;
  const saved = {
    position: body.style.position,
    top: body.style.top,
    left: body.style.left,
    width: body.style.width,
    overflow: body.style.overflow,
    paddingRight: body.style.paddingRight,
  };
  const rootOverflow = root.style.overflow;
  root.style.overflow = "hidden";
  Object.assign(body.style, {
    position: "fixed",
    top: `${-scrollY}px`,
    left: `${-scrollX}px`,
    width: "100%",
    overflow: "hidden",
    paddingRight: `${padding + scrollbar}px`,
  });
  return () => {
    Object.assign(body.style, saved);
    root.style.overflow = rootOverflow;
    const behavior = root.style.scrollBehavior;
    root.style.scrollBehavior = "auto";
    window.scrollTo(scrollX, scrollY);
    root.style.scrollBehavior = behavior;
  };
}

function focusable(dialog: HTMLDialogElement) {
  return [
    ...dialog.querySelectorAll<HTMLElement>(
      "button, input, select, textarea, a[href], summary, [tabindex]",
    ),
  ].filter(
    (element) =>
      element.tabIndex >= 0 &&
      !element.matches(":disabled, [hidden], [inert]") &&
      element.getClientRects().length > 0 &&
      getComputedStyle(element).visibility !== "hidden",
  );
}

/** Native top-layer dialog: viewport positioning, inert background and shared focus/scroll lifecycle. */
export default function Modal({
  open,
  onDismiss,
  labelledBy,
  className = "",
  initialFocus,
  dismissOnBackdrop = false,
  children,
}: Props) {
  const ref = useRef<HTMLDialogElement>(null);
  const dismiss = useRef(onDismiss);
  dismiss.current = onDismiss;
  const startedOutside = useRef(false);

  useLayoutEffect(() => {
    const dialog = ref.current;
    if (!open || !dialog) return;
    const previous = activeModals[activeModals.length - 1] || closingModal;
    const focused =
      document.activeElement instanceof HTMLElement
        ? document.activeElement
        : null;
    // When one dialog replaces another (registration -> token, rotation -> token),
    // preserve the original dashboard trigger instead of a now-hidden dialog button.
    const entry: ActiveModal = {
      dialog,
      returnFocus: previous ? previous.returnFocus : focused,
    };
    if (!unlockPage) unlockPage = lockPage();
    closingModal = null;
    activeModals.push(entry);
    dialog.showModal();
    dialog.scrollTop = 0;
    const first = initialFocus
      ? dialog.querySelector<HTMLElement>(initialFocus)
      : focusable(dialog)[0];
    (first || dialog).focus({ preventScroll: true });

    return () => {
      const index = activeModals.indexOf(entry);
      if (index !== -1) activeModals.splice(index, 1);
      if (dialog.open) dialog.close();
      if (!activeModals.length) closingModal = entry;
      // Resolve after sibling effects, so closing one dialog cannot steal focus
      // from the replacement opening in the same React commit.
      queueMicrotask(() => {
        const top = activeModals[activeModals.length - 1];
        if (top) {
          if (!top.dialog.contains(document.activeElement))
            (focusable(top.dialog)[0] || top.dialog).focus({
              preventScroll: true,
            });
        } else if (closingModal === entry) {
          closingModal = null;
          unlockPage?.();
          unlockPage = null;
          if (entry.returnFocus?.isConnected)
            entry.returnFocus.focus({ preventScroll: true });
        }
      });
    };
  }, [open, initialFocus]);

  const outside = (x: number, y: number) => {
    const bounds = ref.current!.getBoundingClientRect();
    return (
      x < bounds.left || x > bounds.right || y < bounds.top || y > bounds.bottom
    );
  };

  return createPortal(
    <dialog
      ref={ref}
      className={`decision-dialog ${className}`.trim()}
      aria-labelledby={labelledBy}
      aria-modal="true"
      tabIndex={-1}
      onCancel={(event) => {
        event.preventDefault();
        dismiss.current();
      }}
      onPointerDown={(event) => {
        startedOutside.current =
          event.target === event.currentTarget &&
          outside(event.clientX, event.clientY);
      }}
      onPointerUp={(event) => {
        if (
          dismissOnBackdrop &&
          startedOutside.current &&
          event.target === event.currentTarget &&
          outside(event.clientX, event.clientY)
        )
          dismiss.current();
        startedOutside.current = false;
      }}
      onKeyDown={(event) => {
        if (event.key !== "Tab") return;
        const items = focusable(event.currentTarget);
        const first = items[0];
        const last = items[items.length - 1];
        if (!first) {
          event.preventDefault();
          event.currentTarget.focus();
        } else if (
          event.shiftKey &&
          (document.activeElement === first ||
            document.activeElement === event.currentTarget)
        ) {
          event.preventDefault();
          last.focus();
        } else if (
          !event.shiftKey &&
          (document.activeElement === last ||
            document.activeElement === event.currentTarget)
        ) {
          event.preventDefault();
          first.focus();
        }
      }}
    >
      {children}
    </dialog>,
    document.body,
  );
}
