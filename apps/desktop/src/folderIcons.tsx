// Folder icons: Font Awesome Free solid icons (CC BY 4.0, see
// THIRD_PARTY_NOTICES.md). Only the path data is used and drawn as our own
// inline <svg>: no Font Awesome runtime, no injected <style> (the CSP allows
// none), nothing loaded from the network.
import type { IconDefinition } from "@fortawesome/free-solid-svg-icons";
import {
  faBook,
  faBell,
  faBox,
  faBriefcase,
  faBuilding,
  faBuildingColumns,
  faCalendar,
  faCamera,
  faCar,
  faCartShopping,
  faChartLine,
  faCloud,
  faCode,
  faCoins,
  faComments,
  faCreditCard,
  faDatabase,
  faEnvelope,
  faFilm,
  faFlask,
  faGamepad,
  faGear,
  faGlobe,
  faGraduationCap,
  faHeart,
  faHouse,
  faKey,
  faLaptop,
  faLeaf,
  faLock,
  faMobileScreen,
  faMusic,
  faPaw,
  faPhone,
  faPlane,
  faPrint,
  faServer,
  faShieldHalved,
  faStar,
  faStethoscope,
  faStore,
  faTag,
  faTerminal,
  faTrash,
  faUser,
  faUsers,
  faUtensils,
  faWallet,
  faWifi,
} from "@fortawesome/free-solid-svg-icons";

/** Choices in the picker, in this order, with a Turkish name each. The key
 *  stored in the vault is the icon's Font Awesome name ("briefcase"). */
const CHOICES: [IconDefinition, string][] = [
  [faHouse, "Ev"],
  [faUser, "Kişisel"],
  [faUsers, "Aile / ekip"],
  [faBriefcase, "İş"],
  [faBuilding, "Şirket"],
  [faBuildingColumns, "Banka"],
  [faCreditCard, "Kart"],
  [faWallet, "Cüzdan"],
  [faCoins, "Para"],
  [faChartLine, "Yatırım"],
  [faEnvelope, "E-posta"],
  [faComments, "Mesajlaşma"],
  [faPhone, "Telefon"],
  [faGlobe, "Web"],
  [faCloud, "Bulut"],
  [faServer, "Sunucu"],
  [faDatabase, "Veritabanı"],
  [faCode, "Geliştirme"],
  [faTerminal, "Terminal"],
  [faLaptop, "Bilgisayar"],
  [faMobileScreen, "Mobil"],
  [faWifi, "Ağ"],
  [faKey, "Anahtar"],
  [faLock, "Kilit"],
  [faShieldHalved, "Güvenlik"],
  [faGamepad, "Oyun"],
  [faMusic, "Müzik"],
  [faFilm, "Film"],
  [faCamera, "Fotoğraf"],
  [faBook, "Kitap"],
  [faGraduationCap, "Okul"],
  [faCartShopping, "Alışveriş"],
  [faStore, "Mağaza"],
  [faTag, "Etiket"],
  [faPlane, "Seyahat"],
  [faCar, "Araba"],
  [faStethoscope, "Sağlık"],
  [faHeart, "Favori"],
  [faStar, "Yıldız"],
  [faCalendar, "Takvim"],
  [faBell, "Bildirim"],
  [faGear, "Ayarlar"],
  [faFlask, "Deneme"],
  [faBox, "Arşiv"],
  [faPrint, "Yazıcı"],
  [faUtensils, "Yemek"],
  [faPaw, "Evcil hayvan"],
  [faLeaf, "Doğa"],
  [faTrash, "Çöp kutusu"],
];

export const FOLDER_ICONS = CHOICES.map(([def, label]) => ({ key: def.iconName, label, def }));

const BY_KEY = new Map(FOLDER_ICONS.map((i) => [i.key as string, i.def]));

/** One Font Awesome icon as an inline SVG, sized like our other icons. */
export function FaIcon({ def, size = 16 }: { def: IconDefinition; size?: number }) {
  const [w, h, , , path] = def.icon;
  const paths = Array.isArray(path) ? path : [path];
  return (
    <svg
      width={size}
      height={size}
      viewBox={`0 0 ${w} ${h}`}
      fill="currentColor"
      aria-hidden="true"
      className="ic"
    >
      {paths.map((d, i) => (
        <path key={i} d={d} />
      ))}
    </svg>
  );
}

/** The folder's chosen icon, or null for an unknown / unset key (the caller
 *  shows the default folder icon). */
export function folderIconDef(key: string | null | undefined): IconDefinition | null {
  return (key && BY_KEY.get(key)) || null;
}
